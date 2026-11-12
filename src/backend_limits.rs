//! How many requests each backend has in flight at once, for the whole
//! process.
//!
//! `backend.max_connections` (else `connection_pool.max_connections_per_host`)
//! is one limit per backend, shared by every transport: the TCP listeners and
//! the HTTP/3 and WebTransport paths each had a client of their own, and only
//! the second enforced it. A request takes its place before it is sent and
//! keeps it until its response body has been sent on or the exchange is
//! abandoned: it travels with the connection's lease (`backend_client`), so
//! a streamed body counts for as long as it streams. A request that cannot
//! have a place within `connection_pool.acquire_timeout_ms` is refused.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{BackendConfig, ProxyConfig};
use crate::metrics::PoolLoad;

/// What a backend's places have been used for, kept across a change of its
/// limit.
#[derive(Default)]
struct Usage {
    /// Requests that have had a place
    acquired: AtomicU64,
    /// Requests holding one now
    holding: AtomicU64,
    /// Requests waiting for one now
    waiting: AtomicU64,
    /// Requests refused for want of one
    refused: AtomicU64,
}

struct Places {
    cap: usize,
    semaphore: Arc<Semaphore>,
    usage: Arc<Usage>,
}

struct Limits {
    /// Each backend's places, by name
    backends: DashMap<String, Places>,
    /// For a backend that sets no limit of its own
    default_cap: RwLock<usize>,
    /// How long a request waits for a place
    wait: RwLock<Duration>,
}

static LIMITS: LazyLock<Limits> = LazyLock::new(|| Limits {
    backends: DashMap::new(),
    default_cap: RwLock::new(100),
    wait: RwLock::new(Duration::from_secs(5)),
});

/// A request's place on a backend, given back when it drops.
pub struct Place {
    _permit: OwnedSemaphorePermit,
    usage: Arc<Usage>,
}

impl Drop for Place {
    fn drop(&mut self) {
        self.usage.holding.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts a request among the waiting while it waits.
struct Waiting(Arc<Usage>);

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Apply `[connection_pool]`, at startup and on every reload.
///
/// A backend no longer configured (by name, or as a load-balancer pool member by address)
/// loses its places; one whose limit changed gets a new set on its next
/// request, and requests holding the old ones finish as they are.
pub fn configure(config: &ProxyConfig) {
    *LIMITS.default_cap.write() = config.connection_pool.max_connections_per_host.max(1);
    *LIMITS.wait.write() = Duration::from_millis(config.connection_pool.acquire_timeout_ms);
    let pool_members: std::collections::HashSet<String> = config
        .backend_pools
        .values()
        .flat_map(|pool| &pool.servers)
        .filter_map(|server| server.address.parse::<std::net::SocketAddr>().ok())
        .map(|addr| format!("{}:{}", addr.ip(), addr.port()))
        .collect();
    LIMITS
        .backends
        .retain(|name, _| config.backends.contains_key(name) || pool_members.contains(name));
}

fn cap_of(backend: &BackendConfig) -> usize {
    if backend.max_connections > 0 {
        backend.max_connections as usize
    } else {
        *LIMITS.default_cap.read()
    }
}

/// `backend`'s places, made (or remade, keeping their usage) when its limit
/// is not the one they were made for.
fn places_of(backend: &BackendConfig) -> (Arc<Semaphore>, Arc<Usage>) {
    let cap = cap_of(backend);
    if let Some(places) = LIMITS.backends.get(&backend.name) {
        if places.cap == cap {
            return (Arc::clone(&places.semaphore), Arc::clone(&places.usage));
        }
    }
    let mut entry = LIMITS
        .backends
        .entry(backend.name.clone())
        .or_insert_with(|| Places {
            cap,
            semaphore: Arc::new(Semaphore::new(cap)),
            usage: Arc::default(),
        });
    if entry.cap != cap {
        entry.cap = cap;
        entry.semaphore = Arc::new(Semaphore::new(cap));
    }
    (Arc::clone(&entry.semaphore), Arc::clone(&entry.usage))
}

/// A place for one request to `backend`, held until the [`Place`] drops.
pub async fn acquire(backend: &BackendConfig) -> anyhow::Result<Place> {
    let (semaphore, usage) = places_of(backend);
    let wait = *LIMITS.wait.read();
    let permit = match semaphore.clone().try_acquire_owned() {
        Ok(permit) => Ok(permit),
        Err(tokio::sync::TryAcquireError::Closed) => {
            Err(anyhow::anyhow!("backend {} closed", backend.name))
        }
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            usage.waiting.fetch_add(1, Ordering::Relaxed);
            let _waiting = Waiting(Arc::clone(&usage));
            match tokio::time::timeout(wait, semaphore.acquire_owned()).await {
                Ok(Ok(permit)) => Ok(permit),
                Ok(Err(e)) => Err(anyhow::anyhow!("backend {} closed: {e}", backend.name)),
                Err(_) => {
                    usage.refused.fetch_add(1, Ordering::Relaxed);
                    Err(anyhow::anyhow!(
                        "Timed out after {}ms waiting for a connection slot on backend {}",
                        wait.as_millis(),
                        backend.name
                    ))
                }
            }
        }
    }?;
    usage.acquired.fetch_add(1, Ordering::Relaxed);
    usage.holding.fetch_add(1, Ordering::Relaxed);
    Ok(Place {
        _permit: permit,
        usage,
    })
}

/// Every backend's load now, by name (for the metrics).
pub fn load() -> Vec<(String, PoolLoad)> {
    LIMITS
        .backends
        .iter()
        .map(|entry| {
            let usage = &entry.value().usage;
            (
                entry.key().clone(),
                PoolLoad {
                    total: usage.acquired.load(Ordering::Relaxed),
                    active: usage.holding.load(Ordering::Relaxed),
                    waiting: usage.waiting.load(Ordering::Relaxed),
                    refused: usage.refused.load(Ordering::Relaxed),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_backend_has_so_many_requests_in_flight() {
        let backend: BackendConfig = toml::from_str(
            "name = \"backend-limits-test\"\ntype = \"http1\"\naddress = \"127.0.0.1:9\"\nmax_connections = 2\n",
        )
        .unwrap();
        let a = acquire(&backend).await.unwrap();
        let _b = acquire(&backend).await.unwrap();
        *LIMITS.wait.write() = Duration::from_millis(50);
        assert!(
            acquire(&backend).await.is_err(),
            "a third waits, then is refused"
        );
        drop(a);
        assert!(acquire(&backend).await.is_ok());
        let (_, load) = load()
            .into_iter()
            .find(|(name, _)| name == "backend-limits-test")
            .unwrap();
        assert_eq!(
            (load.total, load.active, load.waiting, load.refused),
            (3, 1, 0, 1)
        );

        // A raised limit applies to the next request
        let raised: BackendConfig = toml::from_str(
            "name = \"backend-limits-test\"\ntype = \"http1\"\naddress = \"127.0.0.1:9\"\nmax_connections = 3\n",
        )
        .unwrap();
        let _c = acquire(&raised).await.unwrap();
        let _d = acquire(&raised).await.unwrap();
        let _e = acquire(&raised).await.unwrap();
    }
}
