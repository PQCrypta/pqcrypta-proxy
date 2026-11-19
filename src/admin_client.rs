//! One request to this node's admin API from the command line.
//!
//! `pqcrypta-proxy --admin METHOD PATH [--admin-body JSON]` reads the
//! configuration's `[admin]` section and sends the request with the
//! credentials it names: the bearer token (`auth_token`, else the token the
//! proxy generated into `generated_token_path`) and, where `hmac_secret` is
//! set, the proof of possession (`route_gate::admin_request_signature`, which covers the body) with a
//! fresh timestamp and nonce. Scripts on the node call it rather than
//! building the signature themselves.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use crate::config::AdminConfig;

/// The response: its status and body.
#[derive(Debug)]
pub struct AdminResponse {
    pub status: u16,
    pub body: String,
}

/// Send one request to the admin API the configuration at `config_path`
/// describes.
pub async fn send_from_config(
    config_path: &Path,
    method: &str,
    path_and_query: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", config_path.display()))?;
    let (config, _ignored) = crate::config::parse_config_str(&content)
        .map_err(|e| anyhow::anyhow!("parsing {}: {e}", config_path.display()))?;
    send(&config.admin, method, path_and_query, body).await
}

/// Where a client on this host reaches the admin API: its bind address, or
/// the loopback address of the same family when it binds every address.
fn reachable(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    }
}

/// Send one request to the admin API `config` describes.
pub async fn send(
    config: &AdminConfig,
    method: &str,
    path_and_query: &str,
    body: Option<&str>,
) -> anyhow::Result<AdminResponse> {
    anyhow::ensure!(config.enabled, "[admin] enabled is false on this node");
    anyhow::ensure!(
        !config.require_mtls,
        "[admin] require_mtls is set: the client certificate authenticates, so use a client \
         that presents one"
    );
    anyhow::ensure!(
        path_and_query.starts_with('/'),
        "the path {path_and_query:?} does not start with /"
    );
    let method = reqwest::Method::from_bytes(method.to_ascii_uppercase().as_bytes())
        .map_err(|_| anyhow::anyhow!("{method:?} is not an HTTP method"))?;
    let addr = reachable(
        config
            .socket_addr()
            .map_err(|e| anyhow::anyhow!("[admin] bind_address: {e}"))?,
    );
    let token = match &config.auth_token {
        Some(token) => Some(token.clone()),
        None => std::fs::read_to_string(&config.generated_token_path)
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;
    let mut request = client.request(method.clone(), format!("http://{addr}{path_and_query}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(secret) = &config.hmac_secret {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let signature = crate::route_gate::admin_request_signature(
            secret,
            method.as_str(),
            path_and_query,
            &timestamp,
            &nonce,
            body.unwrap_or_default().as_bytes(),
        );
        request = request
            .header("x-admin-signature", signature)
            .header("x-admin-timestamp", timestamp)
            .header("x-admin-nonce", nonce);
    }
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
    }
    let response = request.send().await?;
    Ok(AdminResponse {
        status: response.status().as_u16(),
        body: response.text().await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_bind_is_reached_on_loopback() {
        assert_eq!(
            reachable("0.0.0.0:8082".parse().unwrap()),
            "127.0.0.1:8082".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            reachable("[::]:8082".parse().unwrap()),
            "[::1]:8082".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            reachable("127.0.0.1:8082".parse().unwrap()),
            "127.0.0.1:8082".parse::<SocketAddr>().unwrap()
        );
    }
}
