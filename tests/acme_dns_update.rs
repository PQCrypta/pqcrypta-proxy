//! The ACME DNS updater against a real DNS server: publish a challenge TXT
//! record by TSIG-signed UPDATE, see it served, withdraw it, see it gone.
//!
//! Ignored by default: it needs a server that takes signed updates for a
//! zone. Run against one, a throwaway knotd for example:
//!
//! ```text
//! PQC_DNS_UPDATE_SERVER=127.0.0.1:15353 PQC_DNS_UPDATE_KEY_NAME=acme-test \
//! PQC_DNS_UPDATE_SECRET_FILE=/tmp/acme-test/secret PQC_DNS_UPDATE_OWNER=_acme-challenge.www.example.test \
//!   cargo test --test acme_dns_update -- --ignored
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use pqcrypta_proxy::acme_dns::{DnsUpdateConfig, DnsUpdater};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

/// The TXT strings at `owner` from `server`, over TCP
async fn txt_at(server: SocketAddr, owner: &str) -> Vec<String> {
    let mut query = vec![0x51, 0x7a, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in owner.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 16, 0, 1]);
    let mut stream = tokio::net::TcpStream::connect(server).await.unwrap();
    let mut framed = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    stream.write_all(&framed).await.unwrap();
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await.unwrap();
    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut msg).await.unwrap();
    // Every TXT string in the answer: skip the question, then read each RR
    let answers = u16::from_be_bytes([msg[6], msg[7]]);
    let mut at = 12;
    let skip_name = |msg: &[u8], mut at: usize| loop {
        let l = msg[at];
        if l == 0 {
            return at + 1;
        }
        if l & 0xC0 == 0xC0 {
            return at + 2;
        }
        at += 1 + usize::from(l);
    };
    at = skip_name(&msg, at) + 4;
    let mut out = Vec::new();
    for _ in 0..answers {
        at = skip_name(&msg, at);
        let rtype = u16::from_be_bytes([msg[at], msg[at + 1]]);
        let rdlength = usize::from(u16::from_be_bytes([msg[at + 8], msg[at + 9]]));
        let rdata = &msg[at + 10..at + 10 + rdlength];
        if rtype == 16 {
            out.push(String::from_utf8_lossy(&rdata[1..]).into_owned());
        }
        at += 10 + rdlength;
    }
    out
}

#[tokio::test]
#[ignore = "needs a DNS server that takes signed updates (see the module docs)"]
async fn a_challenge_record_is_published_and_withdrawn() {
    let config = DnsUpdateConfig {
        server: env("PQC_DNS_UPDATE_SERVER"),
        key_name: env("PQC_DNS_UPDATE_KEY_NAME"),
        algorithm: std::env::var("PQC_DNS_UPDATE_ALGORITHM")
            .unwrap_or_else(|_| "hmac-sha256".into()),
        secret_file: env("PQC_DNS_UPDATE_SECRET_FILE").into(),
        propagation_timeout_secs: 10,
        ttl: 60,
    };
    let server: SocketAddr = config.server.parse().unwrap();
    let owner = env("PQC_DNS_UPDATE_OWNER");
    let updater = DnsUpdater::from_config(&config).unwrap();
    let value = format!("test-{}", std::process::id());

    let record = updater.record(&owner, &value).await.unwrap();
    updater.publish(&record).await.unwrap();
    assert!(
        txt_at(server, &owner).await.contains(&value),
        "the server serves the published value"
    );
    updater.withdraw(&record).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !txt_at(server, &owner).await.contains(&value),
        "the value is gone after the withdrawal"
    );

    // A wrong secret is refused by the server, and the refusal is reported
    let wrong = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(wrong.path(), "d3Jvbmcgc2VjcmV0IGZvciB0aGlzIGtleSEhISE=\n").unwrap();
    let bad = DnsUpdater::from_config(&DnsUpdateConfig {
        secret_file: wrong.path().to_path_buf(),
        ..config
    })
    .unwrap();
    let err = bad.publish(&record).await.unwrap_err().to_string();
    assert!(
        err.contains("TSIG") || err.contains("refused") || err.contains("not signed"),
        "{err}"
    );
}
