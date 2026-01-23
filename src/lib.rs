// Crate-level lint configuration for pedantic lints
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::needless_continue)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::use_self)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::single_match_else)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::option_map_or_none)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
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
#![allow(clippy::wildcard_imports)]
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
//! - Supports hybrid Post-Quantum Cryptography (PQC) key exchange
//! - Routes WebTransport streams and datagrams to various backend types
//! - Provides hot-reload of configuration and TLS certificates
//! - Exposes admin API for health, metrics, and management

pub mod admin;
pub mod compression;
pub mod config;
pub mod fingerprint;
pub mod handlers;
pub mod http3_features;
pub mod http_listener;
pub mod load_balancer;
pub mod pqc_tls;
pub mod proxy;
pub mod quic_listener;
pub mod security;
pub mod tls;
pub mod tls_acceptor;
pub mod webtransport_server;

// Re-export commonly used types
pub use compression::{compression_middleware, CompressionConfig, CompressionState};
pub use config::{ConfigManager, ProxyConfig};
pub use load_balancer::{
    BackendPool as LbBackendPool, BackendServer, LoadBalancer, PoolStats, SelectionContext,
    SessionCookieConfig, extract_session_cookie,
};
pub use fingerprint::{FingerprintExtractor, FingerprintResult, FingerprintStats, Ja3Fingerprint};
pub use http3_features::{
    early_hints_middleware, http3_features_middleware, CoalescingState, EarlyHintsState,
    Http3FeaturesState, PriorityState,
};
#[cfg(feature = "pqc")]
pub use http_listener::run_http_listener_pqc;
pub use http_listener::{run_http_listener, run_http_redirect_server, run_tls_passthrough_server};
pub use pqc_tls::{verify_pqc_support, PqcKemAlgorithm, PqcStatus, PqcTlsProvider};
pub use proxy::BackendPool;
pub use security::{security_middleware, SecurityState};
pub use tls::TlsProvider;
pub use tls_acceptor::{FingerprintedConnection, FingerprintingTlsAcceptor};
pub use webtransport_server::WebTransportServer;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");
