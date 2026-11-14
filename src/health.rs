//! Backend health, asked on each backend's own interval in the background
//! rather than when someone reads the result.
//!
//! A backend with `health_check` set is asked that path, a GET over the
//! transport its requests take (a raw TCP backend is connected to instead),
//! every `health_check_interval_secs`, by one task that follows the
//! configuration through reloads ([`HealthMonitor::spawn`]). A server of a
//! `health_aware` pool is asked its pool's `health_check_path` the same way,
//! or connected to where the pool names none, every
//! `health_check_interval_secs` of the pool ([`crate::load_balancer`]). The
//! admin API's `/health` and `/backends` and the `pqcrypta_backend_up` metric
//! read what the probes recorded, so a request to them asks no backend
//! anything.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use dashmap::DashMap;
use http::{Method, Request};
use http_body_util::{BodyExt, Full};
use tracing::{info, warn};

use crate::backend_client::BackendClient;
use crate::config::{BackendConfig, BackendType, ProxyConfig};

/// What one probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It answered: the HTTP status, or 0 where a connection was the check.
    Up(u16),
    /// It did not, and why.
    Down(String),
}

impl Outcome {
    /// Whether the backend answered as healthy.
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self, Self::Up(_))
    }

    /// The outcome in a few words: `HTTP 200`, `connected`, or the reason.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Up(0) => "connected".to_string(),
            Self::Up(status) => format!("HTTP {status}"),
            Self::Down(why) => why.clone(),
        }
    }
}

/// The probes' own client. A probe's backend is marked `disable_pooling`, so
/// every probe opens the connection a new request would and reuses none.
static PROBE_CLIENT: LazyLock<BackendClient<Full<Bytes>>> =
    LazyLock::new(|| BackendClient::new(Duration::ZERO, 0, Duration::from_secs(10)));

/// Half the interval to answer, from one second to ten, so a probe has ended
/// before the next is due.
#[must_use]
pub fn probe_timeout(interval: Duration) -> Duration {
    (interval / 2).clamp(Duration::from_secs(1), Duration::from_secs(10))
}

/// Ask `backend` whether it is up, within `timeout`.
///
/// Where a path is given and the backend speaks HTTP, a GET for it over the
/// transport its requests take; a connection to its address otherwise. Up
/// means a 2xx answer, or an accepted connection.
pub async fn probe(backend: &BackendConfig, path: Option<&str>, timeout: Duration) -> Outcome {
    let asked = async {
        match (path, &backend.backend_type) {
            (
                Some(path),
                BackendType::Http1 | BackendType::Http2 | BackendType::Http3 | BackendType::Unix,
            ) => ask(backend, path).await,
            _ => connect(backend).await.map(|()| 0),
        }
    };
    match tokio::time::timeout(timeout, asked).await {
        Ok(Ok(status)) => Outcome::Up(status),
        Ok(Err(why)) => Outcome::Down(why),
        Err(_) => Outcome::Down(format!("no answer within {} ms", timeout.as_millis())),
    }
}

async fn ask(backend: &BackendConfig, path: &str) -> Result<u16, String> {
    let mut fresh = backend.clone();
    fresh.disable_pooling = true;
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("health check path {path:?}: {e}"))?;
    let (response, lease) = PROBE_CLIENT
        .send(&fresh, request)
        .await
        .map_err(|e| e.to_string())?;
    let status = response.status();
    if response.into_body().collect().await.is_ok() {
        lease.release();
    }
    if status.is_success() {
        Ok(status.as_u16())
    } else {
        Err(format!("HTTP {}", status.as_u16()))
    }
}

async fn connect(backend: &BackendConfig) -> Result<(), String> {
    #[cfg(unix)]
    if backend.backend_type == BackendType::Unix {
        let path = backend
            .address
            .strip_prefix("unix:")
            .unwrap_or(&backend.address);
        return tokio::net::UnixStream::connect(path)
            .await
            .map(drop)
            .map_err(|e| e.to_string());
    }
    tokio::net::TcpStream::connect(&backend.address)
        .await
        .map(drop)
        .map_err(|e| e.to_string())
}

/// A backend's last probe.
#[derive(Debug, Clone)]
pub struct State {
    /// What it found
    pub outcome: Outcome,
    /// When it was asked, for the admin API
    pub checked_at: SystemTime,
    checked: Instant,
}

/// What the probes last recorded for each backend, by name.
#[derive(Debug, Default)]
pub struct HealthMonitor {
    states: DashMap<String, State>,
    in_flight: DashMap<String, ()>,
}

impl HealthMonitor {
    /// Whether `name` is up: what its last probe found. A backend nothing
    /// asks, having no health check, or not asked yet, is taken to be up, as
    /// requests are sent to it.
    #[must_use]
    pub fn healthy(&self, name: &str) -> bool {
        self.states.get(name).is_none_or(|s| s.outcome.is_up())
    }

    /// `name`'s last probe, if it has been asked.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<State> {
        self.states.get(name).map(|s| s.clone())
    }

    /// Ask every backend with a health check on its own interval, with the
    /// configuration `config` returns at each second, so a reload's backends
    /// are asked from then on and a removed one is forgotten. Ends when the
    /// monitor is dropped.
    pub fn spawn<F>(self: &Arc<Self>, config: F)
    where
        F: Fn() -> Arc<ProxyConfig> + Send + 'static,
    {
        let monitor = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(monitor) = monitor.upgrade() else {
                    return;
                };
                monitor.round(&config());
            }
        });
    }

    /// Start the probes that are due under `config`.
    fn round(self: &Arc<Self>, config: &ProxyConfig) {
        self.states.retain(|name, _| {
            config
                .backends
                .get(name)
                .is_some_and(|b| b.health_check.is_some())
        });
        for (name, backend) in &config.backends {
            let Some(path) = backend.health_check.clone() else {
                continue;
            };
            let interval = Duration::from_secs(backend.health_check_interval_secs.max(1));
            let due = self
                .states
                .get(name)
                .is_none_or(|s| s.checked.elapsed() >= interval);
            if !due || self.in_flight.insert(name.clone(), ()).is_some() {
                continue;
            }
            let monitor = Arc::clone(self);
            let (name, backend) = (name.clone(), backend.clone());
            tokio::spawn(async move {
                let outcome = probe(&backend, Some(&path), probe_timeout(interval)).await;
                monitor.record(&name, outcome);
                monitor.in_flight.remove(&name);
            });
        }
    }

    fn record(&self, name: &str, outcome: Outcome) {
        let was_up = self.states.get(name).map(|s| s.outcome.is_up());
        match (&outcome, was_up) {
            (Outcome::Down(why), Some(true) | None) => {
                warn!("Health check: backend {name} is down: {why}");
            }
            (Outcome::Up(_), Some(false)) => info!("Health check: backend {name} is up again"),
            _ => {}
        }
        self.states.insert(
            name.to_string(),
            State {
                outcome,
                checked_at: SystemTime::now(),
                checked: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A backend that answers every request with `status`.
    async fn backend_answering(status: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 2048];
                    let _ = stream.read(&mut head).await;
                    let answer = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                });
            }
        });
        addr
    }

    fn backend(address: std::net::SocketAddr, health_check: Option<&str>) -> BackendConfig {
        let check = health_check.map_or(String::new(), |p| format!("health_check = \"{p}\"\n"));
        toml::from_str(&format!(
            "name = \"b\"\ntype = \"http1\"\naddress = \"{address}\"\nhealth_check_interval_secs = 1\n{check}"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn a_probe_is_up_on_2xx_and_down_otherwise() {
        let ok = backend_answering("200 OK").await;
        let failing = backend_answering("503 Service Unavailable").await;
        let t = Duration::from_secs(2);
        assert_eq!(
            probe(&backend(ok, None), Some("/health"), t).await,
            Outcome::Up(200)
        );
        assert_eq!(
            probe(&backend(failing, None), Some("/health"), t).await,
            Outcome::Down("HTTP 503".to_string())
        );
    }

    #[tokio::test]
    async fn without_a_path_a_probe_connects() {
        let listening = backend_answering("200 OK").await;
        assert_eq!(
            probe(&backend(listening, None), None, Duration::from_secs(2)).await,
            Outcome::Up(0)
        );
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        assert!(!probe(&backend(closed, None), None, Duration::from_secs(2))
            .await
            .is_up());
    }

    /// The monitor asks each backend with a health check, records the answer
    /// for the admin API, leaves one without a check alone (up), and forgets
    /// a backend the configuration no longer has.
    #[tokio::test]
    async fn the_monitor_records_each_backend_and_follows_the_configuration() {
        let ok = backend_answering("200 OK").await;
        let failing = backend_answering("500 Internal Server Error").await;
        let mut config = ProxyConfig::default();
        config
            .backends
            .insert("up".into(), backend(ok, Some("/health")));
        config
            .backends
            .insert("down".into(), backend(failing, Some("/health")));
        config
            .backends
            .insert("unchecked".into(), backend(failing, None));
        let config = Arc::new(std::sync::RwLock::new(Arc::new(config)));
        let monitor = Arc::new(HealthMonitor::default());
        let source = Arc::clone(&config);
        monitor.spawn(move || Arc::clone(&source.read().unwrap()));

        let deadline = Instant::now() + Duration::from_secs(5);
        while (monitor.state("up").is_none() || monitor.state("down").is_none())
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(monitor.state("up").unwrap().outcome, Outcome::Up(200));
        assert!(!monitor.healthy("down"));
        assert_eq!(
            monitor.state("down").unwrap().outcome.describe(),
            "HTTP 500"
        );
        assert!(monitor.state("unchecked").is_none() && monitor.healthy("unchecked"));

        let mut reloaded = (**config.read().unwrap()).clone();
        reloaded.backends.remove("down");
        *config.write().unwrap() = Arc::new(reloaded);
        let deadline = Instant::now() + Duration::from_secs(3);
        while monitor.state("down").is_some() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            monitor.state("down").is_none(),
            "a removed backend is forgotten"
        );
    }
}
