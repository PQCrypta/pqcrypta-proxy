//! PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with Hybrid PQC TLS
//!
//! A production-ready proxy that:
//! - Listens for QUIC connections with HTTP/3 and WebTransport support
//! - Supports hybrid Post-Quantum Cryptography (PQC) key exchange
//! - Routes WebTransport streams and datagrams to various backend types
//! - Provides hot-reload of configuration and TLS certificates
//! - Exposes admin API for health, metrics, and management

pub mod admin;
pub mod config;
pub mod handlers;
pub mod proxy;
pub mod quic_listener;
pub mod tls;
pub mod webtransport_server;

// Re-export commonly used types
pub use config::{ConfigManager, ProxyConfig};
pub use proxy::BackendPool;
pub use tls::TlsProvider;
pub use webtransport_server::WebTransportServer;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
