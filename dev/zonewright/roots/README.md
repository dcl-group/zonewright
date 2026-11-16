# Root certificates compiled into the crate

## `russian_trusted_root_ca.pem`

The root certificate of the Russian Trusted Root CA, the certification authority of the Ministry of
Digital Development and Communications of the Russian Federation. Neither Mozilla's root list nor a
typical operating system's trust store contains it, so an application that must reach a host whose
certificate chains to it would otherwise have to ship the certificate itself. The crate includes the
file with `include_bytes!` (`src/http/roots.rs`) and trusts it only when
`ContextOptions::russian_trusted_root` is set; by default it is not trusted.

Only the root certificate is here. No intermediate certificate is added: `rustls` makes every
certificate in a root store a trust anchor of its own, and a server sends its intermediates itself.

| Field                     | Value                                                                                             |
| ------------------------- | ------------------------------------------------------------------------------------------------- |
| Subject                   | `C=RU, O=The Ministry of Digital Development and Communications, CN=Russian Trusted Root CA`      |
| Issuer                    | the same (self-signed)                                                                            |
| Serial number             | `0x1000` (4096)                                                                                   |
| Valid from                | 2022-03-01 21:04:15 UTC                                                                           |
| Valid until               | 2032-02-27 21:04:15 UTC                                                                           |
| Key                       | RSA, 4096 bits; signature `sha256WithRSAEncryption`                                               |
| Basic constraints         | CA, path length 4                                                                                 |
| SHA-256 (DER)             | `D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31` |
| SHA-1 (DER)               | `8F:F9:15:CC:AB:7B:C1:6F:8C:5C:80:99:D5:3E:0E:11:5B:3A:EC:2F`                                     |
| DER length                | 1478 bytes                                                                                        |
| SHA-256 of the file (PEM) | `936a43fea6e8e525bcc0f81acd9c3d21b4fc4b9b68acea7906d698005afc6504`                                |

The file is the official download unchanged, byte for byte (PEM with CRLF line endings and no final
line break).

### Origin and checks

- Downloaded on 2026-11-16 from `https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt`,
  the address linked from `https://www.gosuslugi.ru/crt`.
- Cross-checked the same day against two further sources:
  - the second official file, `https://gu-st.ru/content/Other/doc/russian_trusted_root_ca.cer`:
    byte-identical to the first, and so the same DER certificate;
  - the certificate's entry on crt.sh (ID 6316640888), which lists the same SHA-256 fingerprint.
- The tests in `src/http/roots.rs` check that the file is exactly one certificate, that it is
  accepted as a trust anchor, its subject, its SHA-256 fingerprint, and that it is not among
  Mozilla's roots. They do not compare its expiry with the current date.

### Replacing it

Before 2032-02-27, or when the authority publishes a new root:

1. Download the new root certificate from the official address above (or the address that page then
   links to) into an empty directory.
2. Compute its SHA-256 fingerprint over the DER encoding, for example
   `openssl x509 -in <file> -noout -fingerprint -sha256`, and compare it with at least two
   independent sources: a second official file or page of the authority, and a public certificate
   index such as crt.sh. Stop if any of them disagrees.
3. Replace `russian_trusted_root_ca.pem` with the downloaded file, unchanged.
4. Update the table and the section above, the fingerprint constant in the tests of
   `src/http/roots.rs`, and the values in the rustdoc of `ContextOptions::russian_trusted_root` and
   in the module documentation of `src/http/roots.rs`.
5. Run the tests and check that `cargo package --list -p zonewright` still lists the file.

When Mozilla's list takes the root in, the test `the_russian_root_is_not_among_mozillas` fails; the
file and the option can then be retired.
