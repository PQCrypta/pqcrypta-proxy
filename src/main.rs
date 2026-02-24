// Crate-level lint configuration
// SEC-A07: Safety-relevant lints (cast_possible_truncation, cast_sign_loss,
// cast_precision_loss, wildcard_imports) have been removed from this allow-list
// and are now enforced crate-wide.  Any remaining suppressions below apply only
// to style/pedantic lints that do not have security implications.
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::needless_continue)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::use_self)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::single_match_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::option_map_or_none)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::unnecessary_debug_formatting)]
#![allow(clippy::unused_self)]
#![allow(clippy::format_push_string)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::manual_strip)]
#![allow(clippy::bool_comparison)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::explicit_iter_loop)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::similar_names)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::op_ref)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::type_complexity)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::branches_sharing_code)]
#![allow(clippy::ref_option_ref)]
#![allow(clippy::unused_async)]
#![allow(clippy::if_not_else)]
#![allow(clippy::ignored_unit_patterns)]
#![allow(clippy::ref_option)]
#![allow(clippy::trivially_copy_pass_by_ref)]

//! `PQCrypta` Proxy - QUIC/HTTP3/WebTransport Proxy with Hybrid PQC TLS
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

// Use the library crate instead of re-declaring modules
use pqcrypta_proxy::acme;
use pqcrypta_proxy::admin::AdminServer;
use pqcrypta_proxy::config::{ConfigManager, ConfigReloadEvent, ProxyConfig};
use pqcrypta_proxy::metrics;
use pqcrypta_proxy::ocsp;
use pqcrypta_proxy::pqc_tls::{verify_pqc_support, PqcTlsProvider};
use pqcrypta_proxy::proxy::BackendPool;
use pqcrypta_proxy::quic_listener::QuicListener;
use pqcrypta_proxy::tls::TlsProvider;
use pqcrypta_proxy::webtransport_server::WebTransportServer;
use pqcrypta_proxy::SecurityState;
use pqcrypta_proxy::{
    run_http_listener, run_http_listener_with_fingerprint, run_http_redirect_server,
    run_tls_passthrough_server,
};
#[cfg(feature = "pqc")]
use pqcrypta_proxy::{run_http_listener_pqc, run_http_listener_pqc_with_fingerprint};

/// PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS
#[derive(Parser, Debug)]
#[command(name = "pqcrypta-proxy")]
#[command(version, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(
        short,
        long,
        default_value = "/etc/pqcrypta/config.toml",
        env = "PQCRYPTA_CONFIG"
    )]
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

    /// M-2: Explicitly allow backends with tls_skip_verify = true.
    /// This flag MUST be set when any backend disables TLS certificate verification.
    /// Without it the proxy will refuse to start when an insecure backend is found.
    /// Never use this in production; it enables full man-in-the-middle of backend traffic.
    #[arg(long, env = "PQCRYPTA_ALLOW_INSECURE_BACKENDS")]
    allow_insecure_backends: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // SR-08: Install aws-lc-rs as the default rustls CryptoProvider.
    // This ensures the ML-KEM post-quantum key exchange offered by aws-lc-rs is
    // active for ALL TLS paths, including QUIC/HTTP3.  Previously ring was
    // installed here even though Cargo.toml declared aws-lc-rs as the preferred
    // PQC provider; that mismatch meant the QUIC listener did not benefit from
    // the hybrid PQC key exchange available via aws-lc-rs.
    rustls::crypto::aws_lc_rs::default_provider()
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

    // M-2: Warn loudly for every backend that disables TLS certificate verification,
    // and refuse to start unless --allow-insecure-backends was explicitly passed.
    {
        let insecure_backends: Vec<&str> = config
            .backends
            .values()
            .filter(|b| b.tls_skip_verify)
            .map(|b| b.name.as_str())
            .collect();

        if !insecure_backends.is_empty() {
            for name in &insecure_backends {
                warn!(
                    "⚠️  Backend '{}' has tls_skip_verify=true — TLS certificate verification \
                     is DISABLED for this backend (full MITM risk)",
                    name
                );
            }
            if args.allow_insecure_backends {
                warn!(
                    "⚠️  --allow-insecure-backends flag set: continuing with {} insecure backend(s). \
                     This MUST NOT be used in production.",
                    insecure_backends.len()
                );
            } else {
                return Err(anyhow::anyhow!(
                    "Startup aborted: backend(s) {:?} have tls_skip_verify=true but \
                     --allow-insecure-backends was not passed. \
                     Either fix the backend TLS configuration or pass \
                     --allow-insecure-backends to acknowledge the risk.",
                    insecure_backends
                ));
            }
        }
    }

    if args.validate {
        info!("Configuration validation successful, exiting");
        return Ok(());
    }

    let config = Arc::new(config);

    // =========================================================================
    // Initialize Access Logger
    // =========================================================================
    pqcrypta_proxy::init_access_logger(
        config.logging.access_log,
        config.logging.access_log_file.clone(),
    );
    if config.logging.access_log {
        info!(
            "Access logging enabled: {:?}",
            config.logging.access_log_file
        );
    }

    // =========================================================================
    // Security Checks (Key Permissions, Provider Verification)
    // =========================================================================
    perform_security_checks(&config).await?;

    // Initialize PQC TLS provider (OpenSSL 3.5 with ML-KEM)
    info!("Initializing PQC TLS provider...");
    let pqc_provider = Arc::new(PqcTlsProvider::new(&config.pqc));
    let pqc_status = pqc_provider.status();

    if pqc_status.available {
        info!("═══════════════════════════════════════════════════════════════");
        info!("  🔐 POST-QUANTUM CRYPTOGRAPHY ENABLED");
        info!("═══════════════════════════════════════════════════════════════");
        info!("  OpenSSL:       {}", pqc_status.openssl_version);
        info!(
            "  Hybrid Mode:   {}",
            if pqc_status.hybrid_mode {
                "Yes (Classical + PQC)"
            } else {
                "No (Pure PQC)"
            }
        );
        if let Some(kem) = &pqc_status.configured_kem {
            info!(
                "  Preferred KEM: {} (NIST Level {})",
                kem.openssl_name(),
                kem.security_level()
            );
        }
        info!("  Available KEMs: {}", pqc_status.available_kems.len());
        info!("  Groups:        {}", pqc_provider.groups_string());
        info!("═══════════════════════════════════════════════════════════════");
    } else if config.pqc.enabled {
        warn!("═══════════════════════════════════════════════════════════════");
        warn!("  ⚠️  PQC REQUESTED BUT NOT AVAILABLE");
        warn!("═══════════════════════════════════════════════════════════════");
        if let Some(err) = &pqc_status.error {
            warn!("  Error: {}", err);
        }
        warn!("  Falling back to classical TLS 1.3");
        warn!("═══════════════════════════════════════════════════════════════");
    } else {
        info!("📝 PQC disabled - using classical TLS 1.3");
    }

    // Initialize TLS provider (rustls for QUIC)
    info!("Initializing TLS provider...");
    let tls_provider = Arc::new(TlsProvider::new(&config.tls, &config.pqc)?);

    if tls_provider.is_pqc_enabled() {
        info!(
            "✅ PQC hybrid key exchange enabled (provider: {})",
            config.pqc.provider
        );
        info!("   Preferred KEM: {}", config.pqc.preferred_kem);
    } else if config.pqc.enabled && !pqc_status.available {
        // Already warned above
    } else if !config.pqc.enabled {
        info!("📝 PQC disabled - using classical TLS 1.3");
    }

    // Create backend pool
    let backend_pool = Arc::new(BackendPool::new(config.clone()));
    info!(
        "Backend pool initialized with {} backends",
        config.backends.len()
    );

    // Create shutdown channels
    let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);
    let (_admin_shutdown_tx, _admin_shutdown_rx) = mpsc::channel::<()>(1);

    // Start configuration file watching
    if args.watch_config {
        config_manager.start_watching()?;
        info!("Configuration file watching enabled");
    }

    // Spawn config reload handler for hot-reload support
    let reload_tls_provider = tls_provider.clone();
    let reload_pqc_provider = pqc_provider.clone();
    tokio::spawn(async move {
        while let Some(event) = reload_rx.recv().await {
            match event {
                ConfigReloadEvent::ConfigReloaded(new_config) => {
                    info!("Configuration reloaded - applying changes");

                    // Update TLS provider with new config
                    if let Err(e) =
                        reload_tls_provider.update_config(&new_config.tls, &new_config.pqc)
                    {
                        error!("Failed to update TLS config: {}", e);
                    } else {
                        info!("TLS configuration updated successfully");
                    }

                    // Update PQC provider with new config
                    reload_pqc_provider.update_config(&new_config.pqc);
                    info!("PQC configuration updated");

                    // Note: BackendPool update requires mutable access
                    // which would require additional synchronization
                    info!("Backend pool will use new config for new connections");
                }
                ConfigReloadEvent::TlsCertsReloaded => {
                    info!("TLS certificates reloaded");
                    if let Err(e) = reload_tls_provider.reload_certificates() {
                        error!("Failed to reload TLS certificates: {}", e);
                    }
                }
                ConfigReloadEvent::ReloadFailed(err) => {
                    error!("Configuration reload failed: {}", err);
                }
            }
        }
    });

    // Spawn periodic certificate reload check
    let cert_check_interval = config.tls.cert_reload_interval_secs;
    if cert_check_interval > 0 {
        let cert_tls_provider = tls_provider.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(cert_check_interval));
            loop {
                interval.tick().await;
                if cert_tls_provider.needs_reload() {
                    info!("TLS certificate change detected, reloading...");
                    if let Err(e) = cert_tls_provider.reload_certificates() {
                        error!("Failed to reload TLS certificates: {}", e);
                    } else {
                        info!("TLS certificates reloaded successfully");
                    }
                }
            }
        });
        info!(
            "Certificate auto-reload enabled (checking every {}s)",
            cert_check_interval
        );
    }

    // Start admin API server
    // Initialize OCSP stapling service if enabled
    let ocsp_service: Option<Arc<ocsp::OcspService>> = if config.ocsp.enabled {
        info!("Initializing OCSP stapling service...");
        let ocsp_config = ocsp::OcspConfig {
            enabled: config.ocsp.enabled,
            refresh_before_expiry: std::time::Duration::from_secs(
                config.ocsp.refresh_before_expiry_secs,
            ),
            min_refresh_interval: std::time::Duration::from_secs(300),
            request_timeout: std::time::Duration::from_secs(config.ocsp.timeout_secs),
            max_retries: config.ocsp.max_retries,
            retry_delay: std::time::Duration::from_secs(config.ocsp.retry_delay_ms / 1000),
        };
        let mut service = ocsp::OcspService::new(ocsp_config);

        // Load certificates for OCSP
        // L-1: Use rustls-pki-types PEM API (replaces unmaintained rustls-pemfile)
        if let Ok(cert_pem) = std::fs::read(&config.tls.cert_path) {
            use rustls::pki_types::CertificateDer;
            use rustls_pki_types::pem::PemObject;
            if let Ok(certs) =
                CertificateDer::pem_reader_iter(&mut std::io::BufReader::new(cert_pem.as_slice()))
                    .collect::<Result<Vec<_>, _>>()
            {
                service.update_certificates(certs);
            }
        }

        // Start the OCSP refresh background task
        if let Err(e) = service.start() {
            error!("Failed to start OCSP service: {}", e);
        } else {
            info!("✅ OCSP stapling service started");
        }
        Some(Arc::new(service))
    } else {
        info!("📝 OCSP stapling disabled in config");
        None
    };

    // Create shared metrics registry
    let metrics_registry = Arc::new(metrics::MetricsRegistry::new());

    // Initialize TLS metrics
    metrics_registry
        .tls
        .set_pqc_status(tls_provider.is_pqc_enabled(), &config.pqc.preferred_kem);

    // Initialize ACME certificate automation service if enabled
    let acme_challenges: Option<
        Arc<parking_lot::RwLock<std::collections::HashMap<String, acme::PendingChallenge>>>,
    >;
    let acme_service: Option<Arc<parking_lot::RwLock<acme::AcmeService>>> = if config.acme.enabled {
        info!("Initializing ACME certificate automation...");
        let mut service = acme::AcmeService::new(config.acme.clone());
        acme_challenges = Some(service.pending_challenges());

        if let Err(e) = service.start() {
            error!("Failed to start ACME service: {}", e);
            None
        } else {
            info!(
                "✅ ACME service started for domains: {:?}",
                config.acme.domains
            );
            Some(Arc::new(parking_lot::RwLock::new(service)))
        }
    } else {
        info!("📝 ACME certificate automation disabled in config");
        acme_challenges = None;
        None
    };

    let admin_server = AdminServer::new(
        config.admin.clone(),
        config_manager.clone(),
        tls_provider.clone(),
        backend_pool.clone(),
        ocsp_service,
        acme_service,
        None, // Rate limiter created per-listener in http_listener
        shutdown_tx.clone(),
        Some(metrics_registry.clone()),
    );

    let admin_handle = tokio::spawn(async move {
        if let Err(e) = admin_server.run().await {
            error!("Admin server error: {}", e);
        }
    });

    // Start HTTP/HTTPS/WebTransport listeners on all configured ports
    let cert_path = config.tls.cert_path.to_string_lossy().to_string();
    let key_path = config.tls.key_path.to_string_lossy().to_string();

    // Collect all ports to listen on
    let mut all_ports = vec![config.server.udp_port];
    all_ports.extend(&config.server.additional_ports);

    info!("═══════════════════════════════════════════════════════════════");
    info!("  🚀 PQCrypta Proxy - Post-Quantum Ready");
    info!("═══════════════════════════════════════════════════════════════");
    info!("  Ports: {:?}", all_ports);
    info!("  Backends:");
    for (name, backend) in &config.backends {
        info!("    - {} → {}", name, backend.address);
    }
    info!("═══════════════════════════════════════════════════════════════");

    // Start HTTP redirect server (port 80 → HTTPS) with ACME challenge support
    if config.http_redirect.enabled {
        let redirect_port = config.http_redirect.port;
        let https_port = config.server.udp_port;
        let challenges = acme_challenges.clone();

        // AUD-02: Pass the allowed_domains list so the redirect server validates
        // the Host header before building the HTTPS URL.
        let redirect_allowed_domains = config.http_redirect.allowed_domains.clone();
        tokio::spawn(async move {
            if let Err(e) = run_http_redirect_server(
                redirect_port,
                https_port,
                challenges,
                redirect_allowed_domains,
            )
            .await
            {
                error!("HTTP redirect server error: {}", e);
            }
        });
    }

    // Start TLS passthrough server if routes are configured
    if !config.passthrough_routes.is_empty() {
        let passthrough_addr: std::net::SocketAddr = format!(
            "{}:{}",
            config.server.bind_address,
            config.server.udp_port // Use primary port for passthrough
        )
        .parse()?;
        let passthrough_config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = run_tls_passthrough_server(passthrough_addr, passthrough_config).await {
                error!("TLS passthrough server error: {}", e);
            }
        });
    }

    // Start HTTPS reverse proxy listeners (TCP) on all ports
    // Priority: PQC+fingerprinting > fingerprinting-only > PQC-only > standard rustls
    let use_pqc_listener = pqc_status.available && config.pqc.enabled;
    let use_fingerprint_listener =
        config.fingerprint.enabled && config.fingerprint.tls_layer_capture;

    // Create shutdown channels for fingerprinting listeners (supports graceful shutdown)
    let mut http_shutdown_senders: Vec<tokio::sync::watch::Sender<()>> = Vec::new();

    for port in all_ports.clone() {
        let bind_addr: std::net::SocketAddr =
            format!("{}:{}", config.server.bind_address, port).parse()?;

        let http_cert = cert_path.clone();
        let http_key = key_path.clone();
        let http_config = config.clone();
        let http_metrics = metrics_registry.clone();

        // Priority 1: PQC + TLS-layer fingerprinting (OpenSSL with ClientHello capture)
        // Combines post-quantum cryptography with early fingerprint blocking
        #[cfg(feature = "pqc")]
        if use_pqc_listener && use_fingerprint_listener {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
            http_shutdown_senders.push(shutdown_tx);
            let http_pqc_provider = pqc_provider.clone();

            tokio::spawn(async move {
                info!(
                    "🔐🔍 Starting PQC+Fingerprinting HTTPS on {} (OpenSSL ML-KEM + JA3/JA4)",
                    bind_addr
                );
                if let Err(e) = run_http_listener_pqc_with_fingerprint(
                    bind_addr,
                    &http_cert,
                    &http_key,
                    http_config,
                    http_pqc_provider,
                    shutdown_rx,
                    http_metrics,
                )
                .await
                {
                    error!(
                        "PQC+Fingerprinting listener error on port {}: {}",
                        bind_addr.port(),
                        e
                    );
                }
            });
            continue;
        }

        // Priority 2: TLS-layer fingerprinting only (Rustls with ClientHello capture)
        // Use when fingerprinting is enabled but PQC is not available/enabled
        if use_fingerprint_listener {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
            http_shutdown_senders.push(shutdown_tx);

            tokio::spawn(async move {
                info!(
                    "🔍 Starting HTTPS reverse proxy on {} (Rustls with TLS-layer fingerprinting)",
                    bind_addr
                );
                if let Err(e) = run_http_listener_with_fingerprint(
                    bind_addr,
                    &http_cert,
                    &http_key,
                    http_config,
                    shutdown_rx,
                    http_metrics,
                )
                .await
                {
                    error!(
                        "Fingerprinting HTTP listener error on port {}: {}",
                        bind_addr.port(),
                        e
                    );
                }
            });
            continue;
        }

        // Priority 3: PQC without fingerprinting (OpenSSL with ML-KEM)
        #[cfg(feature = "pqc")]
        if use_pqc_listener {
            let http_pqc_provider = pqc_provider.clone();
            tokio::spawn(async move {
                info!(
                    "🔐 Starting PQC HTTPS reverse proxy on {} (OpenSSL ML-KEM)",
                    bind_addr
                );
                if let Err(e) = run_http_listener_pqc(
                    bind_addr,
                    &http_cert,
                    &http_key,
                    http_config,
                    http_pqc_provider,
                    http_metrics,
                )
                .await
                {
                    error!(
                        "PQC HTTP listener error on port {}: {}",
                        bind_addr.port(),
                        e
                    );
                }
            });
            continue;
        }

        // Priority 4: Standard Rustls (no PQC, no fingerprinting)
        tokio::spawn(async move {
            info!("🌐 Starting HTTPS reverse proxy on {} (Rustls)", bind_addr);
            if let Err(e) =
                run_http_listener(bind_addr, &http_cert, &http_key, http_config, http_metrics).await
            {
                error!("HTTP listener error on port {}: {}", bind_addr.port(), e);
            }
        });
    }

    // Start QUIC/HTTP3 servers (UDP) on all ports EXCEPT 4433
    // Port 4433 is handled by dedicated WebTransportServer for proper WebTransport support
    let mut quic_shutdown_senders: Vec<mpsc::Sender<()>> = Vec::new();

    for port in all_ports.clone() {
        // Skip port 4433 - it's handled by dedicated WebTransportServer
        if port == 4433 {
            info!("📡 Port 4433 will be handled by dedicated WebTransport server");
            continue;
        }

        // Create config with the specific port for this listener
        let mut quic_config = (*config).clone();
        quic_config.server.udp_port = port;
        let quic_config = Arc::new(quic_config);
        let quic_tls_provider = tls_provider.clone();
        let quic_metrics = metrics_registry.clone();
        // Each QUIC listener gets its own SecurityState (same pattern as HTTP listeners).
        // SecurityState is Clone (backed by Arcs) so shared data is reference-counted.
        let quic_security = SecurityState::new(&quic_config);

        // Create channels for graceful shutdown
        let (quic_shutdown_tx, quic_shutdown_rx) = mpsc::channel::<()>(1);
        let (_reload_tx, reload_rx) = mpsc::channel(1);

        // Store shutdown sender to keep it alive
        quic_shutdown_senders.push(quic_shutdown_tx);

        tokio::spawn(async move {
            match QuicListener::new(
                quic_config.clone(),
                quic_tls_provider,
                quic_shutdown_rx,
                reload_rx,
                quic_metrics,
                quic_security,
            )
            .await
            {
                Ok(listener) => {
                    let addr = match listener.local_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            error!("Failed to get QUIC listener address: {}", e);
                            return;
                        }
                    };
                    info!(
                        "📡 QUIC/HTTP3/WebTransport server started on {} (UDP)",
                        addr
                    );
                    if let Err(e) = listener.run().await {
                        error!("QUIC/HTTP3 listener error on {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to create QUIC/HTTP3 listener on port {}: {}",
                        port, e
                    );
                }
            }
        });
    }

    // Start dedicated WebTransport server on port 4433
    // This uses wtransport crate for proper WebTransport protocol support
    {
        let wt_config = config.clone();
        let wt_backend_pool = Arc::new(BackendPool::new(config.clone()));
        let wt_cert = cert_path.clone();
        let wt_key = key_path.clone();
        let wt_metrics = metrics_registry.clone();

        tokio::spawn(async move {
            // SR-04: Use the configured bind_address instead of a hardcoded "0.0.0.0"
            // so the WebTransport server honours the operator's bind_address setting
            // (e.g. a private NIC) rather than always binding on all interfaces.
            let wt_addr: std::net::SocketAddr = format!("{}:4433", wt_config.server.bind_address)
                .parse()
                .expect("valid WebTransport bind address from config");

            info!("🚀 Starting dedicated WebTransport server on {}", wt_addr);

            match WebTransportServer::new(wt_addr, &wt_cert, &wt_key, wt_config, wt_backend_pool)
                .await
            {
                Ok(server) => {
                    let server = server.with_metrics(wt_metrics);
                    info!("✅ WebTransport server ready on {}", server.local_addr());
                    if let Err(e) = server.run().await {
                        error!("WebTransport server error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to start WebTransport server: {}", e);
                }
            }
        });
    }

    // Build Alt-Svc header value for logging
    let alt_svc_parts: Vec<String> = all_ports
        .iter()
        .map(|p| format!("h3=\":{}\"; ma=86400", p))
        .collect();

    info!("═══════════════════════════════════════════════════════════════");
    info!("  📡 All listeners started:");
    if config.http_redirect.enabled {
        info!(
            "  HTTP Redirect:   0.0.0.0:{} → HTTPS",
            config.http_redirect.port
        );
    }
    for port in &all_ports {
        if use_pqc_listener && use_fingerprint_listener {
            info!(
                "  HTTPS (🔐🔍):    0.0.0.0:{} (PQC ML-KEM + JA3/JA4 fingerprinting)",
                port
            );
        } else if use_fingerprint_listener {
            info!(
                "  HTTPS (🔍):      0.0.0.0:{} (TLS-layer fingerprinting)",
                port
            );
        } else if use_pqc_listener {
            info!(
                "  HTTPS (🔐):      0.0.0.0:{} (PQC ML-KEM hybrid key exchange)",
                port
            );
        } else {
            info!("  HTTPS (TCP):     0.0.0.0:{}", port);
        }
        info!("  QUIC/HTTP3:      0.0.0.0:{} (UDP)", port);
    }
    info!("  Alt-Svc:         {}", alt_svc_parts.join(", "));
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

    // Send shutdown signal to admin server
    // Intentionally ignored: receiver may already be gone during shutdown
    let _ = shutdown_tx.send(()).await;

    // Send shutdown signals to HTTP fingerprinting listeners
    // Intentionally ignored: receivers may already be gone during shutdown
    for http_shutdown_tx in http_shutdown_senders {
        // watch channels don't need await - they use send() not send().await
        let _ = http_shutdown_tx.send(());
    }

    // Send shutdown signals to QUIC listeners
    // Intentionally ignored: receivers may already be gone during shutdown
    for quic_shutdown_tx in quic_shutdown_senders {
        let _ = quic_shutdown_tx.send(()).await;
    }

    // Wait for admin server to stop
    if let Err(e) = admin_handle.await {
        warn!("Admin server task error during shutdown: {}", e);
    }

    // AUD-11 / SEC-A06: Poll active connections and exit as soon as they reach
    // zero, rather than always sleeping for the full timeout duration.  This
    // allows rapid container restarts when the proxy is already idle while still
    // honouring the configured graceful_shutdown_timeout_secs as an upper bound.
    let drain_secs = config.server.graceful_shutdown_timeout_secs;
    info!(
        "Waiting up to {}s for in-flight connections to drain...",
        drain_secs
    );
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
    loop {
        let active = metrics_registry.active_connections();
        if active == 0 {
            info!("All connections drained — proceeding with shutdown");
            break;
        }
        if std::time::Instant::now() >= deadline {
            info!(
                "Drain timeout reached ({} connection(s) still active)",
                active
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    info!("PQCrypta Proxy shutdown complete");
    Ok(())
}

/// Initialize logging
fn init_logging(level: &str, json: bool) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

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
fn print_startup_summary(config: &ProxyConfig, pqc_enabled: bool) {
    info!("═══════════════════════════════════════════════════════════════");
    info!("  PQCrypta Proxy v{}", env!("CARGO_PKG_VERSION"));
    info!("═══════════════════════════════════════════════════════════════");
    info!(
        "  QUIC/HTTP3:    {}:{}",
        config.server.bind_address, config.server.udp_port
    );
    info!(
        "  Admin API:     {}:{}",
        config.admin.bind_address, config.admin.port
    );
    info!(
        "  PQC Enabled:   {}",
        if pqc_enabled { "✅ Yes" } else { "❌ No" }
    );
    info!("  ALPN:          {:?}", config.tls.alpn_protocols);
    info!("  Backends:      {} configured", config.backends.len());
    info!("  Routes:        {} configured", config.routes.len());
    info!("═══════════════════════════════════════════════════════════════");

    if !config.backends.is_empty() {
        info!("  Backends:");
        for (name, backend) in &config.backends {
            info!(
                "    - {} ({:?}): {}",
                name, backend.backend_type, backend.address
            );
        }
    }

    if !config.routes.is_empty() {
        info!("  Routes:");
        for route in &config.routes {
            let name = route.name.as_deref().unwrap_or("unnamed");
            let host = route.host.as_deref().unwrap_or("*");
            let path = route
                .path_prefix
                .as_deref()
                .or(route.path_exact.as_deref())
                .unwrap_or("*");
            let wt = if route.webtransport {
                " [WebTransport]"
            } else {
                ""
            };
            info!(
                "    - {}: {} {} -> {}{}",
                name, host, path, route.backend, wt
            );
        }
    }

    info!("═══════════════════════════════════════════════════════════════");
}

/// L-4: Validate the configured OpenSSL binary path for basic safety properties.
///
/// Checks:
/// - The path is absolute (not a bare name that could be hijacked via PATH)
/// - The file exists and is a regular file
/// - On Unix: the file is not world-writable (prevents binary substitution)
#[cfg(feature = "pqc")]
fn validate_openssl_path(
    openssl_path: &std::path::Path,
    has_warnings: &mut bool,
    has_errors: &mut bool,
) {
    if !openssl_path.is_absolute() {
        error!(
            "  ❌ openssl_path '{}' is not an absolute path — a relative path can be \
             hijacked via PATH manipulation",
            openssl_path.display()
        );
        *has_errors = true;
        return;
    }

    if !openssl_path.exists() {
        // Not an error — the PQC code already falls back gracefully when OpenSSL is absent.
        // The security concern (L-4) is about what the path points to when it *does* exist.
        warn!(
            "  ⚠️  openssl_path '{}' does not exist — PQC via OpenSSL unavailable; \
             will fall back to rustls",
            openssl_path.display()
        );
        *has_warnings = true;
        return;
    }

    if !openssl_path.is_file() {
        warn!(
            "  ⚠️  openssl_path '{}' exists but is not a regular file",
            openssl_path.display()
        );
        *has_warnings = true;
        return;
    }

    // Unix: check that the file is not world-writable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(openssl_path) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                if mode & 0o002 != 0 {
                    warn!(
                        "  ⚠️  openssl_path '{}' is world-writable (mode {:o}) — \
                         this allows any user to replace the binary",
                        openssl_path.display(),
                        mode
                    );
                    *has_warnings = true;
                } else {
                    info!(
                        "  ✅ openssl_path '{}' permissions: OK (mode {:o})",
                        openssl_path.display(),
                        mode
                    );
                }
            }
            Err(e) => {
                warn!(
                    "  ⚠️  Could not stat openssl_path '{}': {}",
                    openssl_path.display(),
                    e
                );
                *has_warnings = true;
            }
        }
    }

    #[cfg(not(unix))]
    {
        info!(
            "  ✅ openssl_path '{}': exists and is absolute",
            openssl_path.display()
        );
    }
}

/// Perform security checks before starting the proxy
///
/// Checks:
/// 1. TLS private key file permissions (should be 0600 or 0400)
/// 2. OpenSSL provider integrity verification (if PQC enabled)
/// 3. PQC capability detection
async fn perform_security_checks(config: &ProxyConfig) -> anyhow::Result<()> {
    use pqcrypta_proxy::pqc_extended::{ExtendedPqcConfig, KeySecurityCheck, PqcCapabilities};
    use std::path::Path;

    info!("═══════════════════════════════════════════════════════════════");
    info!("  🔒 SECURITY CHECKS");
    info!("═══════════════════════════════════════════════════════════════");

    let mut has_warnings = false;
    let mut has_errors = false;

    // =========================================================================
    // 0. L-4: Validate openssl_path before executing the binary
    // =========================================================================
    #[cfg(feature = "pqc")]
    if config.pqc.enabled {
        if let Some(ref openssl_path) = config.pqc.openssl_path {
            validate_openssl_path(openssl_path, &mut has_warnings, &mut has_errors);
        }
    }

    // =========================================================================
    // 1. Check TLS private key file permissions
    // =========================================================================
    if config.pqc.check_key_permissions {
        let key_path = Path::new(&config.tls.key_path);
        let key_check = KeySecurityCheck::check_key_file(key_path, None);

        if key_check.is_secure() {
            info!("  ✅ Key file permissions: SECURE");
        } else {
            for issue in &key_check.issues {
                if config.pqc.strict_key_permissions {
                    error!("  ❌ Key security issue: {}", issue);
                    has_errors = true;
                } else {
                    warn!("  ⚠️  Key security warning: {}", issue);
                    has_warnings = true;
                }
            }
        }
    } else {
        info!("  ⏭️  Key permission checks: SKIPPED (disabled in config)");
    }

    // =========================================================================
    // 2. Verify OpenSSL provider integrity (if PQC enabled)
    // =========================================================================
    #[cfg(feature = "pqc")]
    if config.pqc.enabled && config.pqc.verify_provider {
        // Convert to ExtendedPqcConfig for verification
        let extended_config = ExtendedPqcConfig {
            enabled: config.pqc.enabled,
            openssl_path: config.pqc.openssl_path.clone(),
            openssl_lib_path: config.pqc.openssl_lib_path.clone(),
            ..Default::default()
        };

        match pqcrypta_proxy::pqc_extended::verify_openssl_provider(&extended_config) {
            Ok(()) => {
                info!("  ✅ OpenSSL provider: VERIFIED");
            }
            Err(e) => {
                if config.pqc.fallback_to_classical {
                    warn!("  ⚠️  OpenSSL provider check failed: {}", e);
                    warn!("     Will fall back to classical TLS (rustls)");
                    has_warnings = true;
                } else {
                    error!("  ❌ OpenSSL provider verification failed: {}", e);
                    has_errors = true;
                }
            }
        }
    } else if config.pqc.enabled {
        info!("  ⏭️  OpenSSL provider verification: SKIPPED (disabled in config)");
    }

    // =========================================================================
    // 3. Detect PQC capabilities
    // =========================================================================
    if config.pqc.enabled {
        // Quick PQC support verification
        match verify_pqc_support() {
            Ok(status) => {
                info!(
                    "  ✅ PQC Support: OpenSSL {} with {} KEMs",
                    status.openssl_version,
                    status.available_kems.len()
                );
            }
            Err(e) => {
                warn!("  ⚠️  PQC verification: {}", e);
                has_warnings = true;
            }
        }

        let extended_config = ExtendedPqcConfig {
            enabled: config.pqc.enabled,
            openssl_path: config.pqc.openssl_path.clone(),
            openssl_lib_path: config.pqc.openssl_lib_path.clone(),
            ..Default::default()
        };

        let capabilities = PqcCapabilities::detect(&extended_config);

        info!("  📊 PQC Capabilities:");
        info!(
            "     rustls (aws-lc-rs): {}",
            if capabilities.rustls_available {
                "✅"
            } else {
                "❌"
            }
        );
        info!(
            "     OpenSSL 3.5+:       {}",
            if capabilities.openssl_available {
                "✅"
            } else {
                "❌"
            }
        );

        if let Some(version) = &capabilities.openssl_version {
            info!("     OpenSSL version:    {}", version);
        }

        info!(
            "     Available KEMs:     {}",
            capabilities.available_kems.len()
        );
        info!(
            "     FIPS mode:          {}",
            if capabilities.fips_mode {
                "✅ ENABLED"
            } else {
                "⏹️  disabled"
            }
        );

        // Check minimum security level
        let min_level = pqcrypta_proxy::pqc_extended::SecurityLevel::Level3;
        if let Some(best_kem) = capabilities.best_kem(min_level, config.pqc.require_hybrid) {
            info!(
                "     Best available KEM: {} (Level {})",
                best_kem.openssl_name(),
                best_kem.security_level() as u8
            );
        } else {
            warn!("  ⚠️  No KEM available at minimum security level");
            has_warnings = true;
        }

        // Report any warnings from capability detection
        for warning in &capabilities.warnings {
            warn!("  ⚠️  {}", warning);
            has_warnings = true;
        }
    }

    info!("═══════════════════════════════════════════════════════════════");

    // Fail if strict mode and errors found
    if has_errors {
        return Err(anyhow::anyhow!(
            "Security checks failed. Fix the issues above or disable strict mode."
        ));
    }

    if has_warnings {
        warn!("Security checks completed with warnings - review the issues above");
    } else {
        info!("✅ All security checks passed");
    }

    Ok(())
}
