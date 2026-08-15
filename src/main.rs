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
use pqcrypta_proxy::audit_logger::AuditLogger;
use pqcrypta_proxy::config::{ConfigManager, ConfigReloadEvent, ProxyConfig, TlsMode};
use pqcrypta_proxy::http3_features::EarlyHintsState;
use pqcrypta_proxy::load_balancer::LoadBalancer;
use pqcrypta_proxy::metrics;
use pqcrypta_proxy::ocsp;
#[cfg(feature = "pqc")]
use pqcrypta_proxy::pqc_tls::openssl_pqc;
use pqcrypta_proxy::pqc_tls::{verify_pqc_support, PqcTlsProvider};
use pqcrypta_proxy::proxy::BackendPool;
use pqcrypta_proxy::quic_listener::QuicListener;
use pqcrypta_proxy::rate_limiter::AdvancedRateLimiter;
use pqcrypta_proxy::startup_verify;
use pqcrypta_proxy::tls::TlsProvider;
use pqcrypta_proxy::webtransport_server::WebTransportServer;
use pqcrypta_proxy::ResponseCache;
use pqcrypta_proxy::SecurityState;
use pqcrypta_proxy::{
    run_http_listener, run_http_listener_with_fingerprint_and_resolver, run_http_redirect_server,
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

    /// Environment name for per-env config overlay.
    /// When set, loads <config-dir>/<config-stem>.<env>.toml and merges it over the base config.
    /// Example: --env prod loads /etc/pqcrypta/config.prod.toml
    #[arg(long, env = "PQCRYPTA_ENV")]
    env: Option<String>,

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

/// Entry point. The runtime is built by hand rather than by `#[tokio::main]`
/// so `server.worker_threads` can size the pool: the attribute always takes
/// every core, which made the setting unreachable however it was configured.
/// 0 keeps the all-cores default.
fn main() -> anyhow::Result<()> {
    // The config must be read before the runtime exists, so worker_threads is
    // known when the pool is built. Parse failures are reported by run() in the
    // usual way; a pre-read that fails here just falls back to the default pool
    // size and lets run() produce the real error message.
    let worker_threads = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--config" || w[0] == "-c")
        .map(|w| w[1].clone())
        .or_else(|| std::env::var("PQCRYPTA_CONFIG").ok())
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| toml::from_str::<toml::Value>(&c).ok())
        .and_then(|v| {
            v.get("server")?
                .get("worker_threads")?
                .as_integer()
                .and_then(|n| usize::try_from(n).ok())
        })
        .unwrap_or(0);

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if worker_threads > 0 {
        builder.worker_threads(worker_threads);
    }
    let runtime = builder
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build Tokio runtime: {}", e))?;

    if worker_threads > 0 {
        tracing::debug!(
            "Tokio runtime: {} worker threads (configured)",
            worker_threads
        );
    }

    runtime.block_on(run())
}

async fn run() -> anyhow::Result<()> {
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

    // STEP 15: Apply per-environment config overlay (--env / PQCRYPTA_ENV).
    if let Some(ref env_name) = args.env {
        let base_path = std::path::Path::new(&args.config);
        let base_dir = base_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let base_stem = base_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("config");
        let overlay_path = base_dir.join(format!("{}.{}.toml", base_stem, env_name));
        if overlay_path.exists() {
            config_manager
                .apply_env_overlay(&overlay_path)
                .map_err(|e| anyhow::anyhow!("--env {}: overlay failed: {}", env_name, e))?;
            info!(
                "✅ Applied env overlay {:?} (--env {})",
                overlay_path, env_name
            );
        } else {
            warn!(
                "--env {}: overlay file {:?} not found — using base config only",
                env_name, overlay_path
            );
        }
    }

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

    // Deprecation warning: trusted_internal_cidrs will be removed in a future release.
    if !config.security.trusted_internal_cidrs.is_empty() {
        warn!(
            "DEPRECATION: security.trusted_internal_cidrs is deprecated. \
             {} CIDR(s) are configured. Replace with mTLS client certificate \
             verification (tls.require_client_cert = true) for identity-bound trust. \
             IP-based trust will be removed in a future release.",
            config.security.trusted_internal_cidrs.len()
        );
    }

    // Zero-trust mode: enforce strict startup constraints.
    if config.security.zero_trust_mode {
        info!("Zero-trust mode enabled — validating constraints");
        let mut zt_errors: Vec<String> = Vec::new();

        // 1. No plaintext (terminate) backends.
        for (name, backend) in &config.backends {
            if backend.tls_mode == TlsMode::Terminate {
                zt_errors.push(format!(
                    "backend '{}' uses tls_mode=terminate (plaintext); \
                     zero_trust_mode requires reencrypt or passthrough",
                    name
                ));
            }
        }

        // 2. No trusted_internal_cidrs.
        if !config.security.trusted_internal_cidrs.is_empty() {
            zt_errors.push(
                "security.trusted_internal_cidrs must be empty in zero_trust_mode; \
                 use mTLS client certificates for identity-based trust"
                    .to_string(),
            );
        }

        // 3. require_client_cert must be true.
        if !config.tls.require_client_cert {
            zt_errors.push("tls.require_client_cert must be true in zero_trust_mode".to_string());
        }

        // 4. Admin API must require proof-of-possession.
        if config.admin.hmac_secret.is_none() {
            zt_errors.push(
                "admin.hmac_secret must be set in zero_trust_mode; \
                 bearer-only admin auth is insufficient for zero-trust"
                    .to_string(),
            );
        }

        if !zt_errors.is_empty() {
            for e in &zt_errors {
                error!("zero_trust_mode violation: {}", e);
            }
            anyhow::bail!(
                "Startup aborted: {} zero_trust_mode constraint(s) violated",
                zt_errors.len()
            );
        }
        info!("Zero-trust mode: all constraints satisfied");
    }

    // ── Startup verification of the cryptographic runtime ────────────────────
    //
    // What follows replaces a banner that announced "POST-QUANTUM CRYPTOGRAPHY
    // ENABLED" on the strength of shelling out to an `openssl` binary. That
    // subprocess does not terminate this proxy's TLS — rustls does — so the claim
    // was drawn from the wrong component and could be true while the serving stack
    // offered no PQC at all, or false while it offered it perfectly. Measured on
    // 2026-08-14: three hosts, three different mapped libcryptos, all three
    // negotiating X25519MLKEM768 regardless of any of them.
    //
    // The handshake below uses the same provider the listener will use, so what is
    // attested is what serves.
    let verify_provider = Arc::new(pqcrypta_proxy::tls::build_pqc_provider());
    let tls13_only = config.tls.min_version == "1.3";
    let runtime = startup_verify::verify_runtime(verify_provider, tls13_only);

    startup_verify::render_kx_verification(&runtime, config.pqc.required);

    let sections = vec![
        startup_verify::Section {
            title: "TLS LISTENER",
            rows: vec![
                startup_verify::Row::configured(
                    "TLS minimum",
                    format!("TLS {}", config.tls.min_version),
                ),
                startup_verify::Row::observed("TLS implementation", "rustls / aws-lc-rs"),
                startup_verify::Row::configured(
                    "KX groups offered",
                    runtime.offered_groups.join(", "),
                ),
                startup_verify::Row {
                    name: "PQC handshake".into(),
                    value: if runtime.succeeded() {
                        if runtime.is_post_quantum {
                            "PASS".into()
                        } else {
                            "FAILED — classical group".into()
                        }
                    } else {
                        "FAILED — no handshake".into()
                    },
                    provenance: startup_verify::Provenance::Verified,
                },
                startup_verify::Row::verified(
                    "Negotiated group",
                    runtime.kx_group.clone().unwrap_or_else(|| "none".into()),
                ),
                startup_verify::Row::verified(
                    "Negotiated suite",
                    runtime
                        .cipher_suite
                        .clone()
                        .unwrap_or_else(|| "none".into()),
                ),
                startup_verify::Row::observed("Verification method", "in-memory TLS 1.3 handshake"),
            ],
        },
        // Sourced only from fields that exist. Every row here is CONFIGURED because
        // none of it is exercised at this point in startup — the listeners have not
        // bound yet. Promoting any of these to VERIFIED requires probing the live
        // listener after bind, which is the natural next step for this mechanism and
        // deliberately not faked in the meantime.
        startup_verify::Section {
            title: "QUIC / HTTP3",
            rows: vec![
                startup_verify::Row::configured("UDP port", config.server.udp_port.to_string()),
                startup_verify::Row::configured("Bind address", config.server.bind_address.clone()),
                startup_verify::Row::configured(
                    "Max connections",
                    config.server.max_connections.to_string(),
                ),
            ],
        },
        startup_verify::dynamic_runtime_section(&runtime),
        startup_verify::Section {
            title: "POLICY",
            rows: vec![startup_verify::Row::configured(
                "PQC required",
                if config.pqc.required { "YES" } else { "no" },
            )],
        },
    ];
    startup_verify::render_banner(&sections);

    // Fails closed, and only on evidence.
    startup_verify::enforce_pqc_policy(&runtime, config.pqc.required)?;

    // Verification runs *before* the validate-and-exit, so `--validate` answers the
    // question an operator actually has before a deployment: not "does this file
    // parse" but "will this host give me the security boundary I am claiming". It
    // needs no ports and no privileges, so it can be run on a candidate host ahead of
    // any traffic — and it fails the same way a real start would.
    if args.validate {
        info!("Configuration validation successful, exiting");
        return Ok(());
    }

    // =========================================================================
    // Initialise OpenTelemetry distributed tracing (if enabled)
    //
    // The tracing_opentelemetry subscriber layer was added at startup with a
    // NOOP global provider.  Calling init_otel() here installs a real OTLP
    // provider so all subsequent request-handling spans are exported.
    // =========================================================================
    let otel_provider = if config.otel.enabled {
        match pqcrypta_proxy::otel::init_otel(&config.otel) {
            Ok(provider) => {
                info!(
                    "OpenTelemetry tracing enabled (endpoint: {})",
                    config.otel.otlp_endpoint
                );
                Some(provider)
            }
            Err(e) => {
                warn!("OpenTelemetry init failed — tracing disabled: {}", e);
                None
            }
        }
    } else {
        info!("OpenTelemetry tracing disabled (otel.enabled = false)");
        None
    };

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

    // Publish the ML-DSA certificate-signing switch before anything loads a
    // certificate — the SNI resolver reads it per host as keys come in.
    pqcrypta_proxy::tls::set_ml_dsa_signing_enabled(config.pqc.enable_signatures);
    info!(
        "ML-DSA-87 certificate signatures: {}",
        if config.pqc.enable_signatures {
            "enabled"
        } else {
            "disabled — ML-DSA keys will be rejected"
        }
    );

    // Initialize PQC TLS provider (OpenSSL 3.5 with ML-KEM)
    info!("Initializing PQC TLS provider...");
    let pqc_provider = Arc::new(PqcTlsProvider::new(&config.pqc));
    let pqc_status = pqc_provider.status();

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

    // Shared Early Hints (103) state — created once here and cloned into every
    // QUIC listener so the reload handler below can update preload rules live.
    let early_hints_state = Arc::new(EarlyHintsState::from_http3_config(&config.http3));

    // Spawn config reload handler for hot-reload support
    let reload_tls_provider = tls_provider.clone();
    let reload_pqc_provider = pqc_provider.clone();
    let reload_early_hints = early_hints_state.clone();
    let reload_config_manager = config_manager.clone();
    tokio::spawn(async move {
        while let Some(event) = reload_rx.recv().await {
            match event {
                ConfigReloadEvent::ConfigReloaded(new_config) => {
                    info!("Configuration reloaded - applying changes");

                    // Refresh the central config snapshot. The file-watcher emits
                    // the event but does not update the ArcSwap itself, so do it
                    // here to keep `config_manager.get()` consistent with what we apply.
                    reload_config_manager.store_config(new_config.clone());

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

                    // Update HTTP/3 Early Hints (103) rules live — preconnect
                    // origins and per-host preload resources take effect on the
                    // next request without a restart.
                    reload_early_hints.update_from_http3_config(&new_config.http3);
                    info!("HTTP/3 Early Hints configuration updated");

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
    // Two settings gate stapling: [ocsp].enabled owns the fetch/refresh service
    // and tls.ocsp_stapling is the TLS-side switch. Both must be on — previously
    // tls.ocsp_stapling was read by nothing, so turning it off changed nothing.
    if config.ocsp.enabled && !config.tls.ocsp_stapling {
        info!("OCSP service configured but tls.ocsp_stapling = false — not stapling");
    }
    let ocsp_service: Option<Arc<ocsp::OcspService>> = if config.ocsp.enabled
        && config.tls.ocsp_stapling
    {
        info!("Initializing OCSP stapling service...");
        let ocsp_config = ocsp::OcspConfig {
            enabled: config.ocsp.enabled,
            cache_duration: std::time::Duration::from_secs(config.ocsp.cache_duration_secs),
            refresh_before_expiry: std::time::Duration::from_secs(
                config.ocsp.refresh_before_expiry_secs,
            ),
            min_refresh_interval: std::time::Duration::from_mins(5),
            request_timeout: std::time::Duration::from_secs(config.ocsp.timeout_secs),
            max_retries: config.ocsp.max_retries,
            // from_millis, not from_secs(ms / 1000): the integer division floored
            // any sub-second delay to zero, so a 500 ms setting retried instantly.
            retry_delay: std::time::Duration::from_millis(config.ocsp.retry_delay_ms),
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

    // Build the shared OpenSSL SNI map used by PQC listeners.
    // Created here (before the ACME handler) so both the ACME reload task and
    // the listener loop can hold a clone of the same Arc<RwLock<...>>.
    #[cfg(feature = "pqc")]
    let pqc_sni_map = {
        let certs_dir = config
            .tls
            .cert_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/pqcrypta/certs"));
        openssl_pqc::build_sni_map(certs_dir, &pqc_provider, &config.server.http11_only_hosts)
    };

    // Initialize ACME certificate automation service if enabled
    let acme_challenges: Option<
        Arc<parking_lot::RwLock<std::collections::HashMap<String, acme::PendingChallenge>>>,
    >;
    let acme_service: Option<Arc<parking_lot::RwLock<acme::AcmeService>>> = if config.acme.enabled {
        info!("Initializing ACME certificate automation...");
        let mut service = acme::AcmeService::new(config.acme.clone());
        acme_challenges = Some(service.pending_challenges());

        // Wire ACME cert-update notifications → TLS provider reload
        let (cert_update_tx, mut cert_update_rx) =
            tokio::sync::mpsc::channel::<acme::CertificateUpdate>(16);
        service.set_cert_update_channel(cert_update_tx);
        let acme_tls_provider = tls_provider.clone();
        #[cfg(feature = "pqc")]
        let acme_pqc_sni_map = pqc_sni_map.clone();
        #[cfg(feature = "pqc")]
        let acme_pqc_provider = pqc_provider.clone();
        #[cfg(feature = "pqc")]
        let acme_certs_dir = config
            .tls
            .cert_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/pqcrypta/certs"))
            .to_path_buf();
        #[cfg(feature = "pqc")]
        let acme_http11_only = config.server.http11_only_hosts.clone();
        tokio::spawn(async move {
            while let Some(update) = cert_update_rx.recv().await {
                info!(
                    "ACME cert issued for '{}', reloading SNI resolver",
                    update.domain
                );
                if let Err(e) = acme_tls_provider.reload_certificates() {
                    error!("Failed to reload TLS certificates after ACME update: {}", e);
                }
                // Also hot-reload the OpenSSL SNI map so the TCP listener
                // serves the new cert immediately without a restart.
                #[cfg(feature = "pqc")]
                openssl_pqc::reload_sni_map(
                    &acme_pqc_sni_map,
                    &acme_certs_dir,
                    &acme_pqc_provider,
                    &acme_http11_only,
                );
            }
        });

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

    // P2-fix: Construct the audit logger and pass it to the admin server.
    // Previously this was always None which silently disabled audit logging.
    let audit_logger = Arc::new(AuditLogger::new(&config.logging));

    // Create shared load balancer so admin API and all HTTP listeners share state
    // (canary suspend/resume, weight changes via admin are reflected in live routing)
    let shared_lb = {
        let lb_config = Arc::new(config.load_balancer.clone());
        let lb = Arc::new(LoadBalancer::new(lb_config));
        for (name, pool_config) in &config.backend_pools {
            lb.add_pool(pool_config);
            info!(
                "⚖️  Added backend pool '{}' with {} servers ({})",
                name,
                pool_config.servers.len(),
                pool_config.algorithm
            );
        }
        lb
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
        Some(audit_logger),
        Some(shared_lb.clone()),
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
        let redirect_to_https = config.http_redirect.redirect_to_https;
        tokio::spawn(async move {
            if let Err(e) = run_http_redirect_server(
                redirect_port,
                https_port,
                redirect_to_https,
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
            config.server.effective_bind_address(),
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
            format!("{}:{}", config.server.effective_bind_address(), port).parse()?;

        let http_cert = cert_path.clone();
        let http_key = key_path.clone();
        let http_config = config.clone();
        let http_metrics = metrics_registry.clone();
        let http_lb = shared_lb.clone();
        let http_resolver = std::sync::Arc::clone(&tls_provider.resolver);

        // Priority 1: PQC + TLS-layer fingerprinting (OpenSSL with ClientHello capture)
        // Combines post-quantum cryptography with early fingerprint blocking
        #[cfg(feature = "pqc")]
        if use_pqc_listener && use_fingerprint_listener {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());
            http_shutdown_senders.push(shutdown_tx);
            let http_pqc_provider = pqc_provider.clone();
            let http_sni_map = pqc_sni_map.clone();

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
                    http_lb,
                    http_sni_map,
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
                if let Err(e) = run_http_listener_with_fingerprint_and_resolver(
                    bind_addr,
                    &http_cert,
                    &http_key,
                    http_config,
                    shutdown_rx,
                    http_metrics,
                    http_lb,
                    Some(http_resolver),
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
            let http_sni_map = pqc_sni_map.clone();
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
                    http_lb,
                    http_sni_map,
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
            if let Err(e) = run_http_listener(
                bind_addr,
                &http_cert,
                &http_key,
                http_config,
                http_metrics,
                http_lb,
            )
            .await
            {
                error!("HTTP listener error on port {}: {}", bind_addr.port(), e);
            }
        });
    }

    // Start QUIC/HTTP3 servers (UDP) on all ports EXCEPT the WebTransport port
    // The WebTransport port is handled by dedicated WebTransportServer
    let webtransport_port = config.server.webtransport_port;
    let mut quic_shutdown_senders: Vec<mpsc::Sender<()>> = Vec::new();

    // P1-fix: Create ONE shared SecurityState before the QUIC listener loop.
    // Previously each listener constructed an independent SecurityState, so an IP
    // blocked by one listener was invisible to all others (no shared blocklist,
    // rate-limiter, or connection counter).  SecurityState is #[derive(Clone)]
    // backed entirely by Arc<...> fields — cloning it shares the underlying maps.
    let shared_quic_security = SecurityState::new(&config);

    for port in all_ports.clone() {
        // Skip webtransport_port - it's handled by dedicated WebTransportServer
        if port == webtransport_port {
            info!(
                "📡 Port {} will be handled by dedicated WebTransport server",
                webtransport_port
            );
            continue;
        }

        // Create config with the specific port for this listener
        let mut quic_config = (*config).clone();
        quic_config.server.udp_port = port;
        let quic_config = Arc::new(quic_config);
        let quic_tls_provider = tls_provider.clone();
        let quic_metrics = metrics_registry.clone();
        // Clone the shared SecurityState — all QUIC listeners now share the same
        // underlying DashMaps (blocked IPs, rate limiters, connection counters).
        let quic_security = shared_quic_security.clone();

        // Create channels for graceful shutdown
        let (quic_shutdown_tx, quic_shutdown_rx) = mpsc::channel::<()>(1);
        let (_reload_tx, reload_rx) = mpsc::channel(1);

        // Store shutdown sender to keep it alive
        quic_shutdown_senders.push(quic_shutdown_tx);

        let quic_advanced_rl = Arc::new(AdvancedRateLimiter::new(
            quic_config.advanced_rate_limiting.clone(),
        ));
        let quic_lb = shared_lb.clone();
        let quic_early_hints = early_hints_state.clone();
        let quic_cache = Arc::new(ResponseCache::new(quic_config.cache.clone()));
        if quic_config.cache.enabled {
            info!(
                "💾 Response cache enabled on QUIC port {} (max {}MiB, default TTL {}s)",
                port, quic_config.cache.max_size_mb, quic_config.cache.default_ttl_secs
            );
        }

        tokio::spawn(async move {
            match QuicListener::new(
                quic_config.clone(),
                quic_tls_provider,
                quic_shutdown_rx,
                reload_rx,
                quic_metrics,
                quic_security,
                quic_advanced_rl,
                quic_lb,
                quic_cache,
                quic_early_hints,
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
        // The WebTransport server uses a single cert (no SNI).  Resolution order:
        //   1. Explicit webtransport_cert_path / webtransport_key_path from config.
        //   2. Auto-detect: look for api.<primary-domain>.crt in the certs directory.
        //   3. Fall back to the primary cert.
        let (wt_cert, wt_key) = if let (Some(wt_c), Some(wt_k)) = (
            config.server.webtransport_cert_path.as_ref(),
            config.server.webtransport_key_path.as_ref(),
        ) {
            info!(
                "WebTransport server: using explicit cert {}",
                wt_c.display()
            );
            (
                wt_c.to_string_lossy().to_string(),
                wt_k.to_string_lossy().to_string(),
            )
        } else {
            let wt_certs_dir = std::path::Path::new(&cert_path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("/etc/pqcrypta/certs"));
            let primary_domain = std::path::Path::new(&cert_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            let api_domain = format!("api.{}", primary_domain);
            let api_cert = wt_certs_dir.join(format!("{}.crt", api_domain));
            let api_key = wt_certs_dir.join(format!("{}.key", api_domain));
            if api_cert.exists() && api_key.exists() {
                info!("WebTransport server: using cert for {}", api_domain);
                (
                    api_cert.to_string_lossy().to_string(),
                    api_key.to_string_lossy().to_string(),
                )
            } else {
                (cert_path.clone(), key_path.clone())
            }
        };
        let wt_metrics = metrics_registry.clone();

        let wt_port = webtransport_port;
        tokio::spawn(async move {
            // SR-04: Use the configured bind_address instead of a hardcoded "0.0.0.0"
            // so the WebTransport server honours the operator's bind_address setting
            // (e.g. a private NIC) rather than always binding on all interfaces.
            // P3-fix: use the configurable webtransport_port from ServerConfig instead
            // of the previously hardcoded 4433.
            let wt_addr: std::net::SocketAddr =
                format!("{}:{}", wt_config.server.effective_bind_address(), wt_port)
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

    // SIGHUP handler: reopen log files without restarting (for log rotation)
    #[cfg(unix)]
    tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to install SIGHUP handler");
        loop {
            sighup.recv().await;
            info!("Received SIGHUP — reopening log files");
            if let Some(logger) = pqcrypta_proxy::access_logger::get_access_logger() {
                logger.reopen();
            }
        }
    });

    // ── Post-bind attestation ────────────────────────────────────────────────
    //
    // The startup handshake proved the provider negotiates a post-quantum group. It
    // could not prove that the socket clients will actually reach was built from that
    // provider — a listener assembled down a different path would still have passed.
    // This probes the bound port itself, over a real TCP connection, and is therefore
    // the claim that corresponds to what a customer experiences.
    //
    // Failure is reported, never fatal: by this point the proxy is serving, and
    // aborting a live listener because a self-test could not connect would turn a
    // diagnostic into an outage. `pqc.required` has already gated startup on the
    // provider-level verification, which is the check that can safely refuse to run.
    {
        // The primary HTTPS port. This was `additional_ports.first()`, which picked
        // 4434 — a real TLS listener, but an auxiliary one, so the attestation
        // described a port no client connects to while saying nothing about the one
        // they all do.
        let probe_port = config.server.udp_port;
        let probe_addr = std::net::SocketAddr::from(([127, 0, 0, 1], probe_port));
        let probe_sni = config
            .routes
            .first()
            .and_then(|r| r.host.clone())
            .unwrap_or_else(|| "localhost".to_string());
        let probe = startup_verify::probe_bound_listener(
            probe_addr,
            &probe_sni,
            Arc::new(pqcrypta_proxy::tls::build_pqc_provider()),
            config.tls.min_version == "1.3",
        );
        startup_verify::render_banner(&[startup_verify::bound_listener_section(
            &probe, probe_addr,
        )]);
        if probe.succeeded() && !probe.is_post_quantum {
            warn!(
                "The bound listener negotiated {} — the in-memory verification passed, \
                 so the provider is capable and the listener is not using it.",
                probe.kx_group.as_deref().unwrap_or("?")
            );
        }
    }

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
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
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

    // Flush and shut down OTEL before process exit so buffered spans are exported
    if let Some(provider) = otel_provider {
        pqcrypta_proxy::otel::shutdown_otel(&provider);
    }

    info!("PQCrypta Proxy shutdown complete");
    Ok(())
}

/// Initialize logging with an optional OpenTelemetry layer.
///
/// The `tracing_opentelemetry::layer()` here references the **global** tracer
/// provider which starts as a NOOP.  Once `otel::init_otel()` is called later
/// in `main` (after config is loaded), the global provider is replaced and all
/// subsequent spans are exported via OTLP.  Startup spans created during config
/// loading are silently dropped — this is acceptable.
fn init_logging(level: &str, json: bool) -> anyhow::Result<()> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // tracing_opentelemetry::layer() references the global tracer provider.
    // It is a NOOP until otel::init_otel() replaces the global provider after
    // config is loaded.  Instantiated fresh in each branch so the subscriber
    // type is correctly inferred without needing type erasure via .boxed().
    if json {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .with(tracing_opentelemetry::layer())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_target(true).with_thread_ids(true))
            .with(tracing_opentelemetry::layer())
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
        config.server.effective_bind_address(),
        config.server.udp_port
    );
    info!(
        "  Admin API:     {}:{}",
        config.admin.bind_address, config.admin.port
    );
    info!(
        "  PQC Enabled:   {}",
        if pqc_enabled { "✅ Yes" } else { "❌ No" }
    );
    if config.otel.enabled {
        info!(
            "  OTEL Tracing:  ✅ {} → {}",
            config.otel.service_name, config.otel.otlp_endpoint
        );
    } else {
        info!("  OTEL Tracing:  ❌ Disabled");
    }
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
