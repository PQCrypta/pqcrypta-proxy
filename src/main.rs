//! PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with Hybrid PQC TLS
//!
//! A production-ready proxy that:
//! - Listens for QUIC connections with HTTP/3 and WebTransport support
//! - Supports hybrid Post-Quantum Cryptography (PQC) key exchange via OpenSSL 3.5 + OQS
//! - Routes WebTransport streams and datagrams to HTTP/1.1, HTTP/2, HTTP/3, or Unix socket backends
//! - Provides hot-reload of configuration and TLS certificates
//! - Exposes admin API for health, metrics, and management

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod admin;
mod config;
mod handlers;
mod proxy;
mod quic_listener;
mod tls;

use admin::AdminServer;
use config::ConfigManager;
use proxy::BackendPool;
use quic_listener::QuicListener;
use tls::TlsProvider;

/// PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS
#[derive(Parser, Debug)]
#[command(name = "pqcrypta-proxy")]
#[command(version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/pqcrypta/config.toml", env = "PQCRYPTA_CONFIG")]
    config: PathBuf,

    /// Override UDP port for QUIC listener
    #[arg(long, env = "PQCRYPTA_UDP_PORT")]
    udp_port: Option<u16>,

    /// Override admin API port
    #[arg(long, env = "PQCRYPTA_ADMIN_PORT")]
    admin_port: Option<u16>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", env = "PQCRYPTA_LOG_LEVEL")]
    log_level: String,

    /// Enable JSON log format
    #[arg(long, env = "PQCRYPTA_JSON_LOGS")]
    json_logs: bool,

    /// Disable PQC hybrid key exchange
    #[arg(long)]
    no_pqc: bool,

    /// Enable configuration file watching for hot-reload
    #[arg(long, default_value = "true")]
    watch_config: bool,

    /// Run configuration validation only (don't start server)
    #[arg(long)]
    validate: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args.log_level, args.json_logs)?;

    info!("Starting PQCrypta Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration file: {:?}", args.config);

    // Load configuration
    let (config_manager, mut reload_rx) = ConfigManager::new(&args.config).await?;
    let config_manager = Arc::new(config_manager);

    // Apply CLI overrides
    let mut config = (*config_manager.get()).clone();

    if let Some(port) = args.udp_port {
        config.server.udp_port = port;
        info!("UDP port overridden to: {}", port);
    }

    if let Some(port) = args.admin_port {
        config.admin.port = port;
        info!("Admin port overridden to: {}", port);
    }

    if args.no_pqc {
        config.pqc.enabled = false;
        info!("PQC hybrid key exchange disabled via CLI");
    }

    // Validate configuration
    config.validate()?;
    info!("Configuration validated successfully");

    if args.validate {
        info!("Configuration validation successful, exiting");
        return Ok(());
    }

    let config = Arc::new(config);

    // Initialize TLS provider
    info!("Initializing TLS provider...");
    let tls_provider = Arc::new(TlsProvider::new(&config.tls, &config.pqc)?);

    if tls_provider.is_pqc_enabled() {
        info!("✅ PQC hybrid key exchange enabled (provider: {})", config.pqc.provider);
        info!("   Preferred KEM: {}", config.pqc.preferred_kem);
    } else if config.pqc.enabled {
        warn!("⚠️ PQC requested but not available - using classical TLS");
    } else {
        info!("📝 PQC disabled - using classical TLS 1.3");
    }

    // Create backend pool
    let backend_pool = Arc::new(BackendPool::new(config.clone()));
    info!("Backend pool initialized with {} backends", config.backends.len());

    // Create shutdown channels
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let (admin_shutdown_tx, _admin_shutdown_rx) = mpsc::channel::<()>(1);

    // Create reload channel for QUIC listener
    let (quic_reload_tx, quic_reload_rx) = mpsc::channel(16);

    // Start configuration file watching
    if args.watch_config {
        config_manager.start_watching()?;
        info!("Configuration file watching enabled");
    }

    // Spawn config reload handler
    let config_manager_clone = config_manager.clone();
    let quic_reload_tx_clone = quic_reload_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = reload_rx.recv().await {
            // Forward reload events to QUIC listener
            let _ = quic_reload_tx_clone.send(event).await;
        }
    });

    // Start admin API server
    let admin_server = AdminServer::new(
        config.admin.clone(),
        config_manager.clone(),
        tls_provider.clone(),
        backend_pool.clone(),
        shutdown_tx.clone(),
    );

    let admin_handle = tokio::spawn(async move {
        if let Err(e) = admin_server.run().await {
            error!("Admin server error: {}", e);
        }
    });

    // Start QUIC listener
    let quic_listener = QuicListener::new(
        config.clone(),
        tls_provider.clone(),
        shutdown_rx,
        quic_reload_rx,
    )
    .await?;

    let quic_addr = quic_listener.local_addr()?;
    info!("🚀 QUIC/HTTP3/WebTransport server listening on {}", quic_addr);

    let quic_handle = tokio::spawn(async move {
        if let Err(e) = quic_listener.run().await {
            error!("QUIC listener error: {}", e);
        }
    });

    // Print startup summary
    print_startup_summary(&config, tls_provider.is_pqc_enabled());

    // Wait for shutdown signal
    info!("Press Ctrl+C to shutdown gracefully");
    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = shutdown_signal() => {
            info!("Received shutdown signal, initiating graceful shutdown...");
        }
    }

    // Graceful shutdown
    info!("Shutting down...");

    // Stop config watching
    config_manager.stop_watching();

    // Send shutdown signal to QUIC listener
    let _ = shutdown_tx.send(()).await;

    // Wait for QUIC listener to finish
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), quic_handle).await;

    info!("PQCrypta Proxy shutdown complete");
    Ok(())
}

/// Initialize logging
fn init_logging(level: &str, json: bool) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_target(true).with_thread_ids(true))
            .init();
    }

    Ok(())
}

/// Wait for OS shutdown signal
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
    let mut sigquit = signal(SignalKind::quit()).expect("Failed to install SIGQUIT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM");
        }
        _ = sigquit.recv() => {
            info!("Received SIGQUIT");
        }
    }
}

#[cfg(windows)]
async fn shutdown_signal() {
    use tokio::signal::windows::ctrl_break;

    let mut ctrl_break = ctrl_break().expect("Failed to install Ctrl+Break handler");
    ctrl_break.recv().await;
    info!("Received Ctrl+Break");
}

#[cfg(not(any(unix, windows)))]
async fn shutdown_signal() {
    // Fallback: just wait forever
    std::future::pending::<()>().await;
}

/// Print startup summary
fn print_startup_summary(config: &config::ProxyConfig, pqc_enabled: bool) {
    info!("═══════════════════════════════════════════════════════════════");
    info!("  PQCrypta Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("═══════════════════════════════════════════════════════════════");
    info!("  QUIC/HTTP3:    {}:{}", config.server.bind_address, config.server.udp_port);
    info!("  Admin API:     {}:{}", config.admin.bind_address, config.admin.port);
    info!("  PQC Enabled:   {}", if pqc_enabled { "✅ Yes" } else { "❌ No" });
    info!("  ALPN:          {:?}", config.tls.alpn_protocols);
    info!("  Backends:      {} configured", config.backends.len());
    info!("  Routes:        {} configured", config.routes.len());
    info!("═══════════════════════════════════════════════════════════════");

    if !config.backends.is_empty() {
        info!("  Backends:");
        for (name, backend) in &config.backends {
            info!("    - {} ({:?}): {}", name, backend.backend_type, backend.address);
        }
    }

    if !config.routes.is_empty() {
        info!("  Routes:");
        for route in &config.routes {
            let name = route.name.as_deref().unwrap_or("unnamed");
            let host = route.host.as_deref().unwrap_or("*");
            let path = route.path_prefix.as_deref().or(route.path_exact.as_deref()).unwrap_or("*");
            let wt = if route.webtransport { " [WebTransport]" } else { "" };
            info!("    - {}: {} {} -> {}{}", name, host, path, route.backend, wt);
        }
    }

    info!("═══════════════════════════════════════════════════════════════");
}
