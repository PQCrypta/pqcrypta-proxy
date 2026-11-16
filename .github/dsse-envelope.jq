# A Sigstore bundle (v0.3, as actions/attest-build-provenance writes it) as
# one in-toto line: its DSSE envelope, each signature carrying the bundle's
# signing certificate in PEM, the layout SLSA provenance files use.
.verificationMaterial.certificate.rawBytes as $der
| .dsseEnvelope
| {
    payloadType,
    payload,
    signatures: [.signatures[] | {
      keyid: (.keyid // ""),
      sig,
      cert: ("-----BEGIN CERTIFICATE-----\n" + ([$der | scan(".{1,64}")] | join("\n")) + "\n-----END CERTIFICATE-----\n")
    }]
  }
