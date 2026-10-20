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

    let mut all = true;
    for config in &configs {
        let single = single_list(config);
        let id = config.get(4).copied().unwrap_or_default();
        let kem = pqcrypta_proxy::ech_config::kem_id(config).unwrap_or_default();
        let tcp = tcp(addr, &name, &single, within)
            .await
            .unwrap_or_else(|e| format!("refused ({e:#})"));
        let quic = quic(addr, &name, &single, within)
            .await
            .unwrap_or_else(|e| format!("refused ({e:#})"));
        let ok = tcp == "accepted" && quic == "accepted";
        all &= ok;
        println!(
            "{} config {id:02x} (KEM 0x{kem:04x}) for {}: TCP {tcp}, QUIC {quic}",
            if ok { "✅" } else { "❌" },
            args.name
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

/// One TLS handshake over TCP offering `list`.
async fn tcp(
    addr: SocketAddr,
    name: &ServerName<'static>,
    list: &[u8],
    within: Duration,
) -> anyhow::Result<String> {
    let config = Arc::new(client(list, &[b"h2", b"http/1.1"])?);
    let name = name.clone();
    tokio::task::spawn_blocking(move || {
        let mut sock = TcpStream::connect_timeout(&addr, within).context("connecting")?;
        sock.set_read_timeout(Some(within))?;
        sock.set_write_timeout(Some(within))?;
        let mut conn = rustls::ClientConnection::new(config, name)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        }
        let status = conn.ech_status();
        // A close_notify, so the proxy sees a finished connection
        conn.send_close_notify();
        let _ = conn.write_tls(&mut sock);
        let _ = sock.flush();
        Ok(match status {
            EchStatus::Accepted => "accepted".to_string(),
            other => format!("not accepted ({other:?})"),
        })
    })
    .await?
}

/// One QUIC handshake offering `list`. rustls fails a handshake whose ECH
/// was rejected, so one that completes was accepted.
async fn quic(
    addr: SocketAddr,
    name: &ServerName<'static>,
    list: &[u8],
    within: Duration,
) -> anyhow::Result<String> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client(list, &[b"h3"])?)?;
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let connecting = endpoint.connect(addr, &name.to_str())?;
    let outcome = match tokio::time::timeout(within, connecting).await {
        Ok(Ok(conn)) => {
            conn.close(0u32.into(), b"");
            Ok("accepted".to_string())
        }
        Ok(Err(e)) => Err(anyhow!(e)),
        Err(_) => Err(anyhow!("no answer in {}s", within.as_secs())),
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
