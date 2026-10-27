use alloc::boxed::Box;
use alloc::vec;

use super::ServerConnectionData;
use crate::common_state::Context;
use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::base::PayloadU16;
use crate::msgs::enums::{Compression, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, HandshakeMessagePayload, HandshakePayload, KeyShareEntry,
    Random, ServerNamePayload, SessionId, SupportedProtocolVersions,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::{CommonState, Error, PeerIncompatible, PeerMisbehaved, ProtocolVersion, Side};

#[test]
fn null_compression_required() {
    assert_eq!(
        test_process_client_hello(ClientHelloPayload {
            compression_methods: vec![],
            ..minimal_client_hello()
        }),
        Err(PeerIncompatible::NullCompressionRequired.into()),
    );
}

#[test]
fn server_ignores_sni_with_ip_address() {
    let mut ch = minimal_client_hello();
    ch.extensions.server_name = Some(ServerNamePayload::IpAddress);
    std::println!("{:?}", ch.extensions);
    assert_eq!(test_process_client_hello(ch), Ok(()));
}

#[test]
fn server_rejects_sni_with_illegal_dns_name() {
    let mut ch = minimal_client_hello();
    ch.extensions.server_name = Some(ServerNamePayload::Invalid);
    std::println!("{:?}", ch.extensions);
    assert_eq!(
        test_process_client_hello(ch),
        Err(PeerMisbehaved::ServerNameMustContainOneHostName.into())
    );
}

fn test_process_client_hello(hello: ClientHelloPayload) -> Result<(), Error> {
    let m = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::handshake(HandshakeMessagePayload(HandshakePayload::ClientHello(
            hello,
        ))),
    };
    super::hs::process_client_hello(
        &m,
        false,
        &mut Context {
            common: &mut CommonState::new(Side::Server),
            data: &mut ServerConnectionData::default(),
            sendable_plaintext: None,
        },
    )
    .map(|_| ())
}

#[macro_rules_attribute::apply(test_for_each_provider)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::time::Duration;

    use super::super::*;
    use crate::common_state::KxState;
    use crate::crypto::tls13::OkmBlock;
    use crate::crypto::{
        ActiveKeyExchange, CryptoProvider, KeyExchangeAlgorithm, SupportedKxGroup,
        WebPkiSupportedAlgorithms,
    };
    use crate::enums::{CertificateType, ContentType};
    use crate::msgs::codec::{Codec, Reader};
    use crate::msgs::handshake::{
        CertificatePayloadTls13, PresharedKeyBinder, PresharedKeyIdentity, PresharedKeyOffer,
        PskKeyExchangeModes,
    };
    use crate::msgs::message::{HEADER_SIZE, InboundOpaqueMessage};
    use crate::msgs::persist;
    use crate::pki_types::pem::PemObject;
    use crate::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};
    use crate::server::{AlwaysResolvesServerRawPublicKeys, ServerConfig, ServerConnection};
    use crate::sign::{CertifiedKey, DelegatedCredential, SingleCertAndKey};
    use crate::sync::Arc;
    use crate::tls13::construct_server_verify_message;
    use crate::tls13::key_schedule::{KeyScheduleEarly, derive_traffic_iv, derive_traffic_key};
    use crate::webpki::{verify_tls13_signature, verify_tls13_signature_with_raw_key};
    use crate::{
        CipherSuiteCommon, DigitallySignedStruct, KeyLog, SupportedCipherSuite, Tls12CipherSuite,
        Tls13CipherSuite, version,
    };

    #[cfg(feature = "tls12")]
    #[test]
    fn test_server_rejects_no_extended_master_secret_extension_when_require_ems_or_fips() {
        let provider = super::provider::default_provider();
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        if config.provider.fips() {
            assert!(config.require_ems);
        } else {
            config.require_ems = true;
        }
        let mut conn = ServerConnection::new(config.into()).unwrap();

        let mut ch = minimal_client_hello();
        ch.extensions
            .extended_master_secret_request
            .take();
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets(),
            Err(Error::PeerIncompatible(
                PeerIncompatible::ExtendedMasterSecretExtensionRequired
            ))
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn server_picks_ffdhe_group_when_clienthello_has_no_ffdhe_group_in_groups_ext() {
        let config = ServerConfig::builder_with_provider(ffdhe_provider().into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites
            .push(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.suite());

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn server_picks_ffdhe_group_when_clienthello_has_no_groups_ext() {
        let config = ServerConfig::builder_with_provider(ffdhe_provider().into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites
            .push(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.suite());
        ch.extensions.named_groups.take();

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn server_accepts_client_with_no_ecpoints_extension_and_only_ffdhe_cipher_suites() {
        let config = ServerConfig::builder_with_provider(ffdhe_provider().into())
            .with_protocol_versions(&[&version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();

        let mut ch = minimal_client_hello();
        ch.cipher_suites
            .push(TLS_DHE_RSA_WITH_AES_128_GCM_SHA256.suite());
        ch.extensions.ec_point_formats.take();

        server_chooses_ffdhe_group_for_client_hello(
            ServerConnection::new(config.into()).unwrap(),
            ch,
        );
    }

    fn server_chooses_ffdhe_group_for_client_hello(
        mut conn: ServerConnection,
        client_hello: ClientHelloPayload,
    ) {
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(client_hello),
            )),
        };
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let KxState::Start(skxg) = &conn.kx_state else {
            panic!("unexpected kx_state");
        };
        assert_eq!(skxg.name(), FAKE_FFDHE_GROUP.name());
    }

    #[test]
    fn test_server_requiring_rpk_client_rejects_x509_client() {
        let mut ch = minimal_client_hello();
        ch.extensions.client_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn = ServerConnection::new(server_config_for_rpk().into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }

    #[test]
    fn test_rpk_only_server_rejects_x509_only_client() {
        let mut ch = minimal_client_hello();
        ch.extensions.server_certificate_types = Some(vec![CertificateType::X509]);
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(HandshakeMessagePayload(
                HandshakePayload::ClientHello(ch),
            )),
        };

        let mut conn = ServerConnection::new(server_config_for_rpk().into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerIncompatible::IncorrectCertificateTypeExtension.into(),
        );
    }

    #[test]
    fn second_client_hello_cannot_withdraw_psk_offer() {
        // Per RFC 9846 section 4.2.2, dropping a PreSharedKey offer is not one of the
        // changes a client may make after a HelloRetryRequest.
        let config =
            ServerConfig::builder_with_provider(super::provider::default_provider().into())
                .with_protocol_versions(&[&version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(server_cert(), server_key())
                .unwrap();
        let mut conn = ServerConnection::new(config.into()).unwrap();

        let encode = |hello| {
            Message {
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::handshake(HandshakeMessagePayload(
                    HandshakePayload::ClientHello(hello),
                )),
            }
            .into_wire_bytes()
        };

        // this hello offers a PSK, but no key share for a group we support, so
        // it draws a HelloRetryRequest.
        let mut first = minimal_client_hello();
        first.extensions.key_shares = Some(vec![]);
        first.extensions.preshared_key_modes = Some(PskKeyExchangeModes {
            psk_dhe: true,
            psk: false,
        });
        first.extensions.preshared_key_offer = Some(PresharedKeyOffer::new(
            PresharedKeyIdentity::new(vec![0u8; 16], 0),
            vec![0u8; 32],
        ));
        conn.read_tls(&mut encode(first).as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        // the second hello follows the retry, but drops the PSK offer entirely.
        let mut second = minimal_client_hello();
        second.extensions.preshared_key_modes = Some(PskKeyExchangeModes {
            psk_dhe: true,
            psk: false,
        });
        conn.read_tls(&mut encode(second).as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::MissingPskExtensionInSecondClientHello.into(),
        );
    }

    #[test]
    fn second_client_hello_cannot_change_cipher_suite() {
        // RFC 9846 section 4.2.4 requires the server to negotiate the same cipher suite it
        // named in its HelloRetryRequest, and section 4.2.2 does not let the client vary its
        // offer, so a second hello that withdraws the retried suite cannot be honoured.
        let provider = CryptoProvider {
            cipher_suites: vec![
                super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
                TLS13_AES_128_GCM_SHA256_ALT,
            ],
            ..super::provider::default_provider()
        };
        let config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        let mut conn = ServerConnection::new(config.into()).unwrap();

        let encode = |hello| {
            Message {
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::handshake(HandshakeMessagePayload(
                    HandshakePayload::ClientHello(hello),
                )),
            }
            .into_wire_bytes()
        };

        // this hello has no key share for a group we support, so it draws a
        // HelloRetryRequest naming `TLS13_AES_128_GCM_SHA256`.
        let mut first = minimal_client_hello();
        first.cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        first.extensions.key_shares = Some(vec![]);
        conn.read_tls(&mut encode(first).as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        // the second hello follows the retry, but offers only a different suite. It shares
        // the retried suite's hash, so the transcript stays valid and nothing else objects.
        let mut second = minimal_client_hello();
        second.cipher_suites = vec![TLS13_AES_128_GCM_SHA256_ALT.suite()];
        conn.read_tls(&mut encode(second).as_slice())
            .unwrap();

        assert_eq!(
            conn.process_new_packets().unwrap_err(),
            PeerMisbehaved::CipherSuiteDifferedOnRetry.into(),
        );
    }

    #[test]
    fn early_data_accepted_for_first_psk_identity() {
        let (selected, early_data_accepted) = resume_with_early_data(0);
        assert_eq!(selected, Some(0));
        assert!(early_data_accepted);
    }

    #[test]
    fn early_data_rejected_for_later_psk_identity() {
        // RFC 9846 section 4.3.10: "In order to accept early data, the server MUST have
        // accepted a PSK cipher suite and selected the first key offered in the client's
        // "pre_shared_key" extension." The server may still resume with a later PSK.
        let (selected, early_data_accepted) = resume_with_early_data(1);
        assert_eq!(selected, Some(1));
        assert!(!early_data_accepted);
    }

    /// Offer a resumable PSK at `index` (preceded by unknown identities) along with an
    /// early data request, returning the selected PSK index and whether early data was accepted.
    fn resume_with_early_data(index: usize) -> (Option<u16>, bool) {
        // ensures X25519 is offered irrespective of cfg(feature = "fips"), to match
        // `minimal_client_hello()`
        let provider = CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        };
        let mut config = ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(server_cert(), server_key())
            .unwrap();
        config.max_early_data_size = 1024;

        let SupportedCipherSuite::Tls13(suite) =
            super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
        else {
            unreachable!();
        };

        let secret = [0x42u8; 32];
        let ticket = b"resumable ticket";
        let session = persist::ServerSessionValue::new(
            None,
            ProtocolVersion::TLSv1_3,
            suite.common.suite,
            &secret,
            None,
            None,
            vec![],
            config.current_time().unwrap(),
            0,
        );
        assert!(
            config
                .session_storage
                .put(ticket.to_vec(), session.get_encoding())
        );

        let binder_len = suite.common.hash_provider.output_len();
        let mut identities = vec![PresharedKeyIdentity::new(b"unknown ticket".to_vec(), 0); index];
        identities.push(PresharedKeyIdentity::new(ticket.to_vec(), 0));
        let binders = vec![PresharedKeyBinder::from(vec![0u8; binder_len]); identities.len()];

        let mut ch = minimal_client_hello();
        ch.cipher_suites = vec![suite.common.suite];
        ch.extensions.preshared_key_modes = Some(PskKeyExchangeModes {
            psk_dhe: true,
            psk: false,
        });
        ch.extensions.early_data_request = Some(());
        ch.extensions.preshared_key_offer = Some(PresharedKeyOffer {
            identities,
            binders,
        });
        let mut hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(ch));

        // compute a genuine binder for the resumable PSK over the final ClientHello
        let key_schedule = KeyScheduleEarly::new(suite, &secret);
        let handshake_hash = suite
            .common
            .hash_provider
            .hash(&hmp.encoding_for_binder_signing());
        let binder = key_schedule.resumption_psk_binder_key_and_sign_verify_data(&handshake_hash);
        let HandshakePayload::ClientHello(ch) = &mut hmp.0 else {
            unreachable!();
        };
        ch.preshared_key_offer
            .as_mut()
            .unwrap()
            .binders[index] = PresharedKeyBinder::from(binder.as_ref().to_vec());

        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(hmp),
        };
        let mut conn = ServerConnection::new(config.into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();

        let mut flight = vec![];
        conn.write_tls(&mut flight).unwrap();
        let mut r = Reader::init(&flight[HEADER_SIZE..]);
        let HandshakeMessagePayload(HandshakePayload::ServerHello(server_hello)) =
            HandshakeMessagePayload::read(&mut r).unwrap()
        else {
            panic!("expected ServerHello");
        };

        (
            server_hello.extensions.preshared_key,
            conn.early_data().is_some(),
        )
    }

    static TLS13_AES_128_GCM_SHA256_ALT: SupportedCipherSuite =
        SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256_ALT_INNER);

    /// Differs from `TLS13_AES_128_GCM_SHA256` only in its code point: same hash, same everything else.
    static TLS13_AES_128_GCM_SHA256_ALT_INNER: Tls13CipherSuite =
        match &super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256 {
            SupportedCipherSuite::Tls13(provider) => Tls13CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::Unknown(0xff14),
                    ..provider.common
                },
                ..**provider
            },
            _ => unreachable!(),
        };

    fn server_config_for_rpk() -> ServerConfig {
        let x25519_provider = CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        };
        ServerConfig::builder_with_provider(x25519_provider.into())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
                server_certified_key(),
            ))))
    }

    fn server_certified_key() -> CertifiedKey {
        let key = super::provider::default_provider()
            .key_provider
            .load_private_key(server_key())
            .unwrap();
        let public_key_as_cert = vec![CertificateDer::from(
            key.public_key()
                .unwrap()
                .as_ref()
                .to_vec(),
        )];
        CertifiedKey::new(public_key_as_cert, key)
    }

    fn server_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/rsa-2048/end.key").as_slice(),
        )
        .unwrap()
    }

    fn server_cert() -> Vec<CertificateDer<'static>> {
        vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/rsa-2048/inter.der")[..]),
        ]
    }

    fn ffdhe_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![FAKE_FFDHE_GROUP],
            cipher_suites: vec![TLS_DHE_RSA_WITH_AES_128_GCM_SHA256],
            ..super::provider::default_provider()
        }
    }

    static FAKE_FFDHE_GROUP: &'static dyn SupportedKxGroup = &FakeFfdheGroup;

    #[derive(Debug)]
    struct FakeFfdheGroup;

    impl SupportedKxGroup for FakeFfdheGroup {
        fn name(&self) -> NamedGroup {
            NamedGroup::FFDHE2048
        }

        fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
            Ok(Box::new(ActiveFakeFfdhe))
        }
    }

    #[derive(Debug)]
    struct ActiveFakeFfdhe;

    impl ActiveKeyExchange for ActiveFakeFfdhe {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn complete(
            self: Box<Self>,
            _peer_pub_key: &[u8],
        ) -> Result<crate::crypto::SharedSecret, Error> {
            todo!()
        }

        fn pub_key(&self) -> &[u8] {
            b"ActiveFakeFfdhe pub key"
        }

        fn group(&self) -> NamedGroup {
            NamedGroup::FFDHE2048
        }
    }

    static TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: SupportedCipherSuite =
        SupportedCipherSuite::Tls12(&TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256);

    static TLS12_DHE_RSA_WITH_AES_128_GCM_SHA256: Tls12CipherSuite =
        match &super::provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
            SupportedCipherSuite::Tls12(provider) => Tls12CipherSuite {
                common: CipherSuiteCommon {
                    suite: CipherSuite::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                    ..provider.common
                },
                kx: KeyExchangeAlgorithm::DHE,
                ..**provider
            },
            _ => unreachable!(),
        };

    #[test]
    fn server_sends_the_delegated_credential_a_client_offers() {
        let flight = flight_for(Some(vec![SignatureScheme::ECDSA_NISTP256_SHA256]));
        let dc = &flight.delegated_credential;

        let leaf = &flight.certificate.entries[0];
        assert_eq!(
            leaf.extensions
                .delegated_credential
                .as_ref()
                .map(|p| p.bytes()),
            Some(dc.encoded())
        );
        assert!(
            flight.certificate.entries[1..]
                .iter()
                .all(|e| e.extensions.delegated_credential.is_none())
        );

        // CertificateVerify comes from the delegated key, under the scheme
        // its credential names
        assert_eq!(flight.verify.scheme, dc.scheme());
        let encoded = dc.encoded();
        let spki_len = (usize::from(encoded[6]) << 16)
            | (usize::from(encoded[7]) << 8)
            | usize::from(encoded[8]);
        let spki = SubjectPublicKeyInfoDer::from(&encoded[9..9 + spki_len]);
        verify_tls13_signature_with_raw_key(
            &flight.verify_message,
            &spki,
            &flight.verify,
            &flight.algorithms,
        )
        .unwrap();
    }

    #[test]
    fn server_signs_with_the_certificate_key_unless_a_credential_is_acceptable() {
        // not offered; offered for another scheme
        for offered in [None, Some(vec![SignatureScheme::ED25519])] {
            let flight = flight_for(offered);
            assert!(!flight.certificate.any_delegated_credential());
            assert_eq!(
                flight.verify.scheme,
                SignatureScheme::ECDSA_NISTP384_SHA384
            );
            verify_tls13_signature(
                &flight.verify_message,
                &flight.leaf,
                &flight.verify,
                &flight.algorithms,
            )
            .unwrap();
        }
    }

    /// The server's first flight, decrypted, for a ClientHello offering
    /// `offered` in its delegated_credential extension to a server whose
    /// P-384 certificate carries a P-256 delegated credential.
    struct ServerFlight {
        delegated_credential: DelegatedCredential,
        leaf: CertificateDer<'static>,
        certificate: CertificatePayloadTls13<'static>,
        verify: DigitallySignedStruct,
        verify_message: Vec<u8>,
        algorithms: WebPkiSupportedAlgorithms,
    }

    fn flight_for(offered: Option<Vec<SignatureScheme>>) -> ServerFlight {
        let provider = Arc::new(CryptoProvider {
            kx_groups: vec![super::provider::kx_group::X25519],
            ..super::provider::default_provider()
        });
        let load = |pair: &rcgen::KeyPair| {
            provider
                .key_provider
                .load_private_key(PrivateKeyDer::Pkcs8(pair.serialize_der().into()))
                .unwrap()
        };

        let issuer = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["dc.example".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let leaf = params
            .self_signed(&issuer)
            .unwrap()
            .der()
            .clone();
        // a second entry, to show the credential rides on the end-entity's only
        let mut certified = CertifiedKey::new(vec![leaf.clone(), leaf.clone()], load(&issuer));
        let delegated_credential = DelegatedCredential::delegate(
            &certified,
            load(&rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()),
            UnixTime::since_unix_epoch(Duration::from_secs(946_684_800)),
            UnixTime::since_unix_epoch(Duration::from_secs(4_102_444_800)),
            UnixTime::now(),
            Duration::from_secs(3_600),
        )
        .unwrap();
        certified
            .delegated_credentials
            .push(delegated_credential.clone());

        let secrets = Arc::new(Secrets::default());
        let mut config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.key_log = secrets.clone();

        let mut ch = minimal_client_hello();
        ch.cipher_suites = vec![CipherSuite::TLS13_AES_128_GCM_SHA256];
        ch.extensions.signature_schemes = Some(vec![SignatureScheme::ECDSA_NISTP384_SHA384]);
        ch.extensions.delegated_credential = offered;
        let hmp = HandshakeMessagePayload(HandshakePayload::ClientHello(ch));
        let mut transcript = hmp.get_encoding();
        let ch = Message {
            version: ProtocolVersion::TLSv1_3,
            payload: MessagePayload::handshake(hmp),
        };

        let mut conn = ServerConnection::new(config.into()).unwrap();
        conn.read_tls(&mut ch.into_wire_bytes().as_slice())
            .unwrap();
        conn.process_new_packets().unwrap();
        let mut wire = vec![];
        while conn.wants_write() {
            conn.write_tls(&mut wire).unwrap();
        }

        let SupportedCipherSuite::Tls13(suite) =
            super::provider::cipher_suite::TLS13_AES_128_GCM_SHA256
        else {
            unreachable!();
        };
        let secret = secrets.get("SERVER_HANDSHAKE_TRAFFIC_SECRET");
        let expander = suite
            .hkdf_provider
            .expander_for_okm(&OkmBlock::new(&secret));
        let mut decrypter = suite.aead_alg.decrypter(
            derive_traffic_key(&*expander, suite.aead_alg),
            derive_traffic_iv(&*expander),
        );

        // ServerHello in the clear, a compatibility ChangeCipherSpec, then
        // the encrypted flight
        let mut handshake = Vec::new();
        let mut seq = 0;
        let mut rest = &mut wire[..];
        while !rest.is_empty() {
            let typ = ContentType::from(rest[0]);
            let len = usize::from(u16::from_be_bytes([rest[3], rest[4]]));
            let (record, tail) = core::mem::take(&mut rest).split_at_mut(HEADER_SIZE + len);
            rest = tail;
            let payload = &mut record[HEADER_SIZE..];
            match typ {
                ContentType::Handshake => transcript.extend_from_slice(payload),
                ContentType::ChangeCipherSpec => {}
                ContentType::ApplicationData => {
                    let plain = decrypter
                        .decrypt(
                            InboundOpaqueMessage::new(typ, ProtocolVersion::TLSv1_2, payload),
                            seq,
                        )
                        .unwrap();
                    seq += 1;
                    assert_eq!(plain.typ, ContentType::Handshake);
                    handshake.extend_from_slice(plain.payload);
                }
                other => panic!("unexpected {other:?} record"),
            }
        }

        let mut certificate = None;
        let mut verify = None;
        let mut r = Reader::init(&handshake);
        while r.any_left() {
            let start = r.used();
            let message = HandshakeMessagePayload::read_version(&mut r, ProtocolVersion::TLSv1_3)
                .unwrap();
            match message.0 {
                HandshakePayload::CertificateTls13(c) => certificate = Some(c.into_owned()),
                HandshakePayload::CertificateVerify(dss) => {
                    let hash = suite
                        .common
                        .hash_provider
                        .hash(&transcript);
                    verify = Some((
                        dss,
                        construct_server_verify_message(&hash)
                            .as_ref()
                            .to_vec(),
                    ));
                }
                _ => {}
            }
            transcript.extend_from_slice(&handshake[start..r.used()]);
        }
        let (verify, verify_message) = verify.expect("a CertificateVerify");

        ServerFlight {
            delegated_credential,
            leaf,
            certificate: certificate.expect("a Certificate"),
            verify,
            verify_message,
            algorithms: provider.signature_verification_algorithms,
        }
    }

    /// The traffic secrets a connection logs, by label
    #[derive(Debug, Default)]
    struct Secrets(std::sync::Mutex<Vec<(String, Vec<u8>)>>);

    impl Secrets {
        fn get(&self, label: &str) -> Vec<u8> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|(l, _)| l == label)
                .map(|(_, secret)| secret.clone())
                .unwrap()
        }
    }

    impl KeyLog for Secrets {
        fn log(&self, label: &str, _client_random: &[u8], secret: &[u8]) {
            self.0
                .lock()
                .unwrap()
                .push((label.into(), secret.to_vec()));
        }
    }
}

fn minimal_client_hello() -> ClientHelloPayload {
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_3,
        random: Random::from([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
        ],
        compression_methods: vec![Compression::Null],
        extensions: Box::new(ClientExtensions {
            signature_schemes: Some(vec![SignatureScheme::RSA_PSS_SHA256]),
            named_groups: Some(vec![NamedGroup::X25519, NamedGroup::secp256r1]),
            supported_versions: Some(SupportedProtocolVersions {
                tls12: true,
                tls13: true,
            }),
            key_shares: Some(vec![KeyShareEntry {
                group: NamedGroup::X25519,
                payload: PayloadU16::new(vec![0xab; 32]),
            }]),
            extended_master_secret_request: Some(()),
            ..ClientExtensions::default()
        }),
    }
}
