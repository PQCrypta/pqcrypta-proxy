//! PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with Hybrid PQC TLS
//!
//! A production-ready proxy that:
//! - Listens for QUIC connections with HTTP/3 and WebTransport support
//! - Supports hybrid Post-Quantum Cryptography (PQC) key exchange
//! - Routes WebTransport streams and datagrams to various backend types
//! - Provides hot-reload of configuration and TLS certificates
//! - Exposes admin API for health, metrics, and management

pub mod admin;
pub mod compression;
pub mod config;
pub mod handlers;
pub mod http3_features;
pub mod http_listener;
pub mod pqc_tls;
pub mod proxy;
pub mod quic_listener;
pub mod security;
pub mod tls;
pub mod webtransport_server;

// Re-export commonly used types
pub use compression::{CompressionConfig, CompressionState, compression_middleware};
pub use config::{ConfigManager, ProxyConfig};
pub use http3_features::{
    Http3FeaturesState, EarlyHintsState, PriorityState, CoalescingState,
    http3_features_middleware, early_hints_middleware,
};
pub use http_listener::{run_http_listener, run_http_redirect_server, run_tls_passthrough_server};
#[cfg(feature = "pqc")]
pub use http_listener::run_http_listener_pqc;
pub use proxy::BackendPool;
pub use pqc_tls::{PqcTlsProvider, PqcKemAlgorithm, PqcStatus, verify_pqc_support};
pub use security::{SecurityState, security_middleware};
pub use tls::TlsProvider;
pub use webtransport_server::WebTransportServer;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
