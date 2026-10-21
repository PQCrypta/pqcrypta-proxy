//! Offers every config of an `ECHConfigList` to a running proxy, over TCP and
//! over QUIC, one config at a time, and exits non-zero unless each handshake
//! was accepted: the check `ech-rotate.sh` makes before it publishes a list.
//!
//! The rotation used to publish once the proxy said it had reloaded, and a
//! reload is not a handshake. On 2026-10-20 the proxy reloaded, TCP held the
//! new configs and QUIC still held the ones it started with, and DNS
//! published configs HTTP/3 refused. A client takes a config from the list
//! (rustls the first whose suite it implements, a browser the first it
//! implements at all), so each config is offered on its own: every one
//! published must open, on each transport the HTTPS record advertises.
//!
//! The certificate is verified as a browser verifies it, against the public
//! roots, for the name the encrypted `ClientHello` carries: accepted ECH means
//! the server opened the inner `ClientHello` and answered for that name.

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _};
use clap::Parser;
use rustls::client::{EchConfig, EchMode, EchStatus};
use rustls::pki_types::{EchConfigListBytes, ServerName};

#[derive(Parser)]
#[command(about = "Offer each published ECH config to a proxy over TCP and QUIC")]
struct Args {
    /// The name to ask for inside the encrypted `ClientHello`, one the proxy
    /// serves with this list (pqcrypta.com)
    name: String,
    /// Where the proxy listens, TCP and UDP
    #[arg(long, default_value = "127.0.0.1:443")]
    addr: String,
    /// The UDP port HTTP/3 answers on, where it is not `--addr`'s (the
    /// HTTPS record then names it: `alpn="h3" port=4434`)
    #[arg(long)]
    quic_port: Option<u16>,
    /// The `ECHConfigList` to offer (what is about to be published)
    #[arg(long, default_value = "/etc/pqcrypta/ech-configs/ech-config-list.bin")]
    list: std::path::PathBuf,
    /// Seconds each handshake may take
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();
    match run(&args).await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::FAILURE,
        Err(e) => {
            eprintln!("ech-check: {e:#}");
            std::process::ExitCode::from(2)
        }
    }
}

/// Whether every config opened on both transports.
async fn run(args: &Args) -> anyhow::Result<bool> {
    let list =
        std::fs::read(&args.list).with_context(|| format!("reading {}", args.list.display()))?;
    let configs = entries(&list)?;
    let addr = args
        .addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", args.addr))?
        .next()
        .ok_or_else(|| anyhow!("{} names no address", args.addr))?;
    let name = ServerName::try_from(args.name.clone()).context("the name to ask for")?;
    let within = Duration::from_secs(args.timeout);
    let quic_port = args.quic_port.unwrap_or_else(|| addr.port());

    let mut all = true;
    for config in &configs {
        let single = single_list(config);
        let id = config.get(4).copied().unwrap_or_default();
        let kem = pqcrypta_proxy::ech_config::kem_id(config).unwrap_or_default();
        let tcp = tcp(addr, &name, &single, within).await;
        let quic_addr = SocketAddr::new(addr.ip(), quic_port);
        let quic = quic(quic_addr, &name, &single, within).await;
        let ok = tcp == Outcome::Accepted && quic == Outcome::Accepted;
        all &= ok;
        println!(
            "{} config {id:02x} (KEM 0x{kem:04x}) for {}: TCP {}, QUIC {}",
            if ok { "✅" } else { "❌" },
            args.name,
            tcp.describe(),
            quic.describe()
        );
    }
    Ok(all)
}

/// The `ECHConfigs` of an `ECHConfigList` (RFC 9849 §4: a two-byte length, then
/// each config's version, two-byte length and contents), each as encoded.
fn entries(list: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
    let (len, mut rest) = list
        .split_first_chunk::<2>()
        .ok_or_else(|| anyhow!("ECHConfigList shorter than its length"))?;
    if usize::from(u16::from_be_bytes(*len)) != rest.len() {
        bail!("ECHConfigList length prefix does not match its contents");
    }
    let mut out = Vec::new();
    while !rest.is_empty() {
        let header = rest
            .get(..4)
            .ok_or_else(|| anyhow!("truncated ECHConfig header"))?;
        let end = 4 + usize::from(u16::from_be_bytes([header[2], header[3]]));
        let config = rest
            .get(..end)
            .ok_or_else(|| anyhow!("truncated ECHConfig"))?;
        out.push(config.to_vec());
        rest = &rest[end..];
    }
    if out.is_empty() {
        bail!("ECHConfigList holds no config");
    }
    Ok(out)
}

/// An `ECHConfigList` of the one config.
fn single_list(config: &[u8]) -> Vec<u8> {
    let mut list = u16::try_from(config.len())
        .expect("a config fits in its list")
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(config);
    list
}

/// A client offering ECH with `list` and nothing else: GREASE and a fallback
/// to the outer name would both hide a refusal.
fn client(list: &[u8], alpn: &[&[u8]]) -> anyhow::Result<rustls::ClientConfig> {
    let ech = EchConfig::new(
        EchConfigListBytes::from(list.to_vec()),
        pqcrypta_proxy::ech_config::suites(),
    )
    .context("no HPKE suite here opens this config")?;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        pqcrypta_proxy::tls::build_pqc_provider(),
    ))
    .with_ech(EchMode::Enable(ech))
    .context("ECH needs TLS 1.3")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}

/// What one handshake came to. Told in this program's own words: the
/// libraries' error text is built from what their configuration holds, the
/// client's certificate resolver among it (code scanning, `rust/cleartext-logging`),
/// and a fixed word is what the rotation log needs anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The server opened the inner `ClientHello`
    Accepted,
    /// The server answered for the cover name: it holds no key for the config
    Rejected,
    /// The handshake failed otherwise (certificate, protocol, a closed
    /// connection)
    Failed,
    /// No connection: refused, unreachable, or nothing to connect with
    Unreachable,
    /// No answer within the time allowed
    TimedOut,
}

impl Outcome {
    const fn describe(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected (the server answered for the cover name)",
            Self::Failed => "failed (the handshake did not complete)",
            Self::Unreachable => "unreachable",
            Self::TimedOut => "no answer in time",
        }
    }

    /// A TLS handshake's failure: the ECH rejection rustls reports as
    /// `PeerIncompatible::ServerRejectedEncryptedClientHello`, or another.
    const fn of_tls(e: &rustls::Error) -> Self {
        match e {
            rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_),
            ) => Self::Rejected,
            _ => Self::Failed,
        }
    }

    /// A TCP connection's or TLS-over-TCP handshake's I/O failure.
    fn of_io(e: &std::io::Error) -> Self {
        if let Some(tls) = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            return Self::of_tls(tls);
        }
        match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::TimedOut,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::AddrNotAvailable => Self::Unreachable,
            _ => Self::Failed,
        }
    }
}

/// One TLS handshake over TCP offering `list`.
async fn tcp(
    addr: SocketAddr,
    name: &ServerName<'static>,
    list: &[u8],
    within: Duration,
) -> Outcome {
    let Ok(config) = client(list, &[b"h2", b"http/1.1"]) else {
        return Outcome::Failed;
    };
    let config = Arc::new(config);
    let name = name.clone();
    let handshake = tokio::task::spawn_blocking(move || {
        let mut sock = match TcpStream::connect_timeout(&addr, within) {
            Ok(sock) => sock,
            Err(e) => return Outcome::of_io(&e),
        };
        if sock.set_read_timeout(Some(within)).is_err()
            || sock.set_write_timeout(Some(within)).is_err()
        {
            return Outcome::Failed;
        }
        let Ok(mut conn) = rustls::ClientConnection::new(config, name) else {
            return Outcome::Failed;
        };
        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut sock) {
                return Outcome::of_io(&e);
            }
        }
        let status = conn.ech_status();
        // A close_notify, so the proxy sees a finished connection
        conn.send_close_notify();
        let _ = conn.write_tls(&mut sock);
        let _ = sock.flush();
        if status == EchStatus::Accepted {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        }
    });
    handshake.await.unwrap_or(Outcome::Failed)
}

/// One QUIC handshake offering `list`. rustls fails a handshake whose ECH
/// was rejected, so one that completes was accepted.
async fn quic(
    addr: SocketAddr,
    name: &ServerName<'static>,
    list: &[u8],
    within: Duration,
) -> Outcome {
    let Ok(Ok(crypto)) =
        client(list, &[b"h3"]).map(quinn::crypto::rustls::QuicClientConfig::try_from)
    else {
        return Outcome::Failed;
    };
    let bind = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let Ok(endpoint) = quinn::Endpoint::client(bind) else {
        return Outcome::Unreachable;
    };
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let Ok(connecting) = endpoint.connect(addr, &name.to_str()) else {
        return Outcome::Unreachable;
    };
    let outcome = match tokio::time::timeout(within, connecting).await {
        Ok(Ok(conn)) => {
            conn.close(0u32.into(), b"");
            Outcome::Accepted
        }
        // A TLS failure ends the handshake as a CRYPTO_ERROR transport error;
        // rustls names the ECH rejection in its reason
        Ok(Err(quinn::ConnectionError::TransportError(te)))
            if te.reason.contains("ServerRejectedEncryptedClientHello") =>
        {
            Outcome::Rejected
        }
        Ok(Err(quinn::ConnectionError::TimedOut)) | Err(_) => Outcome::TimedOut,
        Ok(Err(_)) => Outcome::Failed,
    };
    endpoint.wait_idle().await;
    outcome
}

#[cfg(test)]
mod tests {
    use super::{entries, single_list};

    #[test]
    fn a_list_splits_into_its_configs_and_each_stands_alone() {
        let a = [0xfe, 0x0d, 0, 3, 0x64, 1, 2];
        let b = [0xfe, 0x0d, 0, 1, 0xd5];
        let mut list = vec![0, 12];
        list.extend_from_slice(&a);
        list.extend_from_slice(&b);
        let configs = entries(&list).unwrap();
        assert_eq!(configs, [a.to_vec(), b.to_vec()]);
        assert_eq!(single_list(&b), [0, 5, 0xfe, 0x0d, 0, 1, 0xd5]);
        // A length that disagrees, a truncated config and an empty list
        assert!(entries(&[0, 13, 0xfe]).is_err());
        assert!(entries(&[0, 4, 0xfe, 0x0d, 0, 9]).is_err());
        assert!(entries(&[0, 0]).is_err());
    }
}
