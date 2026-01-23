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
mod http_listener;
mod proxy;
mod quic_listener;
mod tls;
mod webtransport_server;

use admin::AdminServer;
use config::ConfigManager;
use http_listener::{run_http_listener, run_http_redirect_server};
use proxy::BackendPool;
use tls::TlsProvider;
use webtransport_server::WebTransportServer;

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
    // Install rustls CryptoProvider before any TLS operations
    // This is required when both ring and aws-lc-rs features are available
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
    let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
    let (_admin_shutdown_tx, _admin_shutdown_rx) = mpsc::channel::<()>(1);

    // Start configuration file watching
    if args.watch_config {
        config_manager.start_watching()?;
        info!("Configuration file watching enabled");
    }

    // Spawn config reload handler (for future hot-reload support)
    tokio::spawn(async move {
        while let Some(_event) = reload_rx.recv().await {
            // Config reload events are logged but not yet forwarded to WebTransport server
            info!("Configuration reload event received");
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

    // Start HTTP/HTTPS/WebTransport listeners on all configured ports
    // This enables standalone operation - replaces nginx entirely
    let cert_path = config.tls.cert_path.to_string_lossy().to_string();
    let key_path = config.tls.key_path.to_string_lossy().to_string();

    // Collect all ports to listen on
    let mut all_ports = vec![config.server.udp_port];
    all_ports.extend(&config.server.additional_ports);

    info!("═══════════════════════════════════════════════════════════════");
    info!("  🚀 STANDALONE PROXY - Replaces nginx entirely!");
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Ports: {:?}", all_ports);
    info!("  Backends:");
    for (name, backend) in &config.backends {
        info!("    - {} → {}", name, backend.address);
    }
    info!("═══════════════════════════════════════════════════════════════");

    // Start HTTP redirect server (port 80 → HTTPS)
    if config.http_redirect.enabled {
        let redirect_port = config.http_redirect.port;
        let https_port = config.server.udp_port;

        tokio::spawn(async move {
            if let Err(e) = run_http_redirect_server(redirect_port, https_port).await {
                error!("HTTP redirect server error: {}", e);
            }
        });
    }

    // Start HTTPS reverse proxy listeners (TCP) on all ports
    for port in all_ports.clone() {
        let bind_addr: std::net::SocketAddr = format!(
            "{}:{}",
            config.server.bind_address,
            port
        ).parse()?;

        let http_cert = cert_path.clone();
        let http_key = key_path.clone();
        let http_config = config.clone();

        tokio::spawn(async move {
            info!("🌐 Starting HTTPS reverse proxy on {} (TCP)", bind_addr);
            if let Err(e) = run_http_listener(bind_addr, &http_cert, &http_key, http_config).await {
                error!("HTTP listener error on port {}: {}", bind_addr.port(), e);
            }
        });
    }

    // Start WebTransport servers (UDP) on all ports
    for port in all_ports.clone() {
        let bind_addr: std::net::SocketAddr = format!(
            "{}:{}",
            config.server.bind_address,
            port
        ).parse()?;

        let wt_cert = cert_path.clone();
        let wt_key = key_path.clone();
        let wt_config = config.clone();
        let wt_backend_pool = backend_pool.clone();

        tokio::spawn(async move {
            match WebTransportServer::new(
                bind_addr,
                &wt_cert,
                &wt_key,
                wt_config,
                wt_backend_pool,
            ).await {
                Ok(server) => {
                    let addr = server.local_addr();
                    info!("📡 WebTransport server started on {} (UDP)", addr);
                    if let Err(e) = server.run().await {
                        error!("WebTransport server error on {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!("Failed to create WebTransport server on {}: {}", bind_addr, e);
                }
            }
        });
    }

    // Build Alt-Svc header value for logging
    let alt_svc_parts: Vec<String> = all_ports.iter()
        .map(|p| format!("h3=\":{}\"; ma=86400", p))
        .collect();

    info!("═══════════════════════════════════════════════════════════════");
    info!("  📡 All listeners started:");
    if config.http_redirect.enabled {
        info!("  HTTP Redirect:   0.0.0.0:{} → HTTPS", config.http_redirect.port);
    }
    for port in &all_ports {
        info!("  HTTPS (TCP):     0.0.0.0:{}", port);
        info!("  WebTransport:    0.0.0.0:{} (UDP)", port);
    }
    info!("  Alt-Svc:         {}", alt_svc_parts.join(", "));
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Routing:");
    info!("    api.pqcrypta.com → 127.0.0.1:3003 (Rust API)");
    info!("    pqcrypta.com     → 127.0.0.1:8080 (Apache)");
    info!("═══════════════════════════════════════════════════════════════");

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

    // Send shutdown signal
    let _ = shutdown_tx.send(()).await;

    // Wait for admin server to stop
    if let Err(e) = admin_handle.await {
        warn!("Admin server task error during shutdown: {}", e);
    }

    // Give spawned tasks time to complete
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

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
