//! The relay's own session to an upstream relay (`[moq] upstream`).
//!
//! A relay that has no local publisher for a namespace asks its upstream,
//! as a client (draft-ietf-moq-transport section 7: a coordinated set of
//! relays acts as one). The session is opened on the first request that
//! needs it and again after it ends, over native QUIC, offering every
//! version this relay speaks. Its SETUP names the upstream URI's AUTHORITY
//! and PATH (sections 9.1.1, 9.1.2), and its TLS uses the post-quantum
//! hybrid key exchange first. Through it the relay SUBSCRIBEs and FETCHes
//! exactly as it does through a local publisher's session.

use std::net::SocketAddr;
use std::sync::{Arc, Weak};

use futures_util::future::BoxFuture;

use super::relay::{NamespacePublisher, Relay, Track};
use super::session::{Session, Settings};
use super::transport::QuicTransport;
use super::version::Version;

/// An upstream relay's `moqt://host[:port]/path` URI (section 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamUri {
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl UpstreamUri {
    pub fn parse(uri: &str) -> anyhow::Result<Self> {
        let rest = uri
            .strip_prefix("moqt://")
            .ok_or_else(|| anyhow::anyhow!("moq.upstream {uri:?} is not a moqt:// URI"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (h, after) = v6.split_once(']').ok_or_else(|| {
                    anyhow::anyhow!("moq.upstream {uri:?}: an unclosed IPv6 literal")
                })?;
                let port = after.strip_prefix(':').map_or(Ok(443), str::parse)?;
                (h.to_string(), port)
            }
            None => match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse()?),
                None => (authority.to_string(), 443),
            },
        };
        if host.is_empty() || path.contains('#') {
            anyhow::bail!("moq.upstream {uri:?} needs a host and no fragment");
        }
        Ok(Self {
            host,
            port,
            path: path.to_string(),
        })
    }

    fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// The relay's link to its upstream: a session made when first needed.
pub struct UpstreamLink {
    uri: UpstreamUri,
    relay: Weak<Relay>,
    settings: Arc<Settings>,
    endpoint: quinn::Endpoint,
    client: quinn::ClientConfig,
    session: tokio::sync::Mutex<Option<Arc<Session<QuicTransport>>>>,
}

impl UpstreamLink {
    /// A link that verifies the upstream against the web PKI's roots.
    pub fn new(
        uri: UpstreamUri,
        relay: &Arc<Relay>,
        settings: Arc<Settings>,
    ) -> anyhow::Result<Arc<Self>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        crypto.alpn_protocols = Version::alpns();
        let client = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));
        Self::with_client(uri, relay, settings, client)
    }

    /// A link with its own QUIC client configuration (its ALPN must list
    /// the versions this relay speaks).
    pub fn with_client(
        uri: UpstreamUri,
        relay: &Arc<Relay>,
        settings: Arc<Settings>,
        client: quinn::ClientConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let endpoint = quinn::Endpoint::client(SocketAddr::from(([0u16; 8], 0)))
            .or_else(|_| quinn::Endpoint::client(SocketAddr::from(([0u8; 4], 0))))?;
        Ok(Arc::new(Self {
            uri,
            relay: Arc::downgrade(relay),
            settings,
            endpoint,
            client,
            session: tokio::sync::Mutex::new(None),
        }))
    }

    /// The open session, or a new one.
    async fn session(&self) -> Result<Arc<Session<QuicTransport>>, String> {
        let mut slot = self.session.lock().await;
        if let Some(s) = slot.as_ref().filter(|s| !s.is_closed()) {
            return Ok(Arc::clone(s));
        }
        let relay = self.relay.upgrade().ok_or("the relay has stopped")?;
        let addr = tokio::net::lookup_host((self.uri.host.as_str(), self.uri.port))
            .await
            .map_err(|e| format!("resolving {}: {e}", self.uri.host))?
            .next()
            .ok_or_else(|| format!("{} has no address", self.uri.host))?;
        let conn = self
            .endpoint
            .connect_with(self.client.clone(), addr, &self.uri.host)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| format!("connecting to {}: {e}", self.uri.authority()))?;
        let alpn = conn
            .handshake_data()
            .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|h| h.protocol)
            .unwrap_or_default();
        let version = Version::from_alpn(&alpn).ok_or("the upstream chose no MOQT version")?;
        let session = Session::new_client(
            QuicTransport(conn, addr),
            version,
            Arc::clone(&relay),
            Arc::clone(&self.settings),
            self.uri.authority(),
            self.uri.path.clone(),
        );
        let run = Arc::clone(&session);
        let shutdown = relay.shutdown_signal();
        tokio::spawn(async move { run.run(shutdown).await });
        if !session.wait_for_setup().await {
            return Err("the upstream closed the session during SETUP".into());
        }
        *slot = Some(Arc::clone(&session));
        Ok(session)
    }
}

/// The link as the relay's publisher of last resort: every namespace no
/// local publisher advertises is asked for upstream.
pub struct UpstreamPublisher(pub Arc<UpstreamLink>);

impl NamespacePublisher for UpstreamPublisher {
    fn subscribe_upstream(
        &self,
        track: Arc<Track>,
        new_group: Option<u64>,
    ) -> BoxFuture<'static, Result<(), (u64, String)>> {
        let link = Arc::clone(&self.0);
        Box::pin(async move {
            let session = link
                .session()
                .await
                .map_err(|e| (super::error::RequestCode::Timeout as u64, e))?;
            session.subscribe_upstream(track, new_group).await
        })
    }

    fn session_id(&self) -> u64 {
        // Not a session of this relay's: its advertisement is never withdrawn
        // with one
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_uris_parse() {
        assert_eq!(
            UpstreamUri::parse("moqt://relay.example:8443/moq").unwrap(),
            UpstreamUri {
                host: "relay.example".into(),
                port: 8443,
                path: "/moq".into()
            }
        );
        assert_eq!(
            UpstreamUri::parse("moqt://relay.example").unwrap().port,
            443
        );
        assert_eq!(
            UpstreamUri::parse("moqt://[2001:db8::1]:4433/x")
                .unwrap()
                .host,
            "2001:db8::1"
        );
        assert!(UpstreamUri::parse("https://relay.example/moq").is_err());
        assert!(UpstreamUri::parse("moqt:///moq").is_err());
    }
}
