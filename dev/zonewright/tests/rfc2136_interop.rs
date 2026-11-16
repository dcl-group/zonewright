//! Cross-checks of the RFC 2136 mock, and of the client, against independent implementations of
//! DNS UPDATE (RFC 2136), TSIG (RFC 8945) and the query protocol (RFC 1035): BIND's `nsupdate`
//! and `dig`.
//!
//! The client and its mock were written from the same reading of those RFCs, so a shared
//! misreading would pass every test in `rfc2136.rs`. Here `nsupdate` writes to the mock and `dig`
//! reads from it, and the client and the tools read what the other wrote.
//!
//! The tests need `/usr/bin/nsupdate` and `/usr/bin/dig`, so they are ignored by default; each
//! fails with a clear message when a binary is missing. They talk only to the mock on an
//! ephemeral port of 127.0.0.1, passed explicitly to both tools. TSIG keys are synthetic,
//! generated per run, and handed to the tools in key files inside a temporary directory that is
//! removed at the end. Every child process is bounded by its own timeouts and is killed after
//! [`CHILD_DEADLINE`].
//!
//! Observed with nsupdate 9.10.6 and DiG 9.10.6 (the builds shipped with macOS) on 2026-11-15.
//! That `nsupdate` accepts `hmac-md5`, `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`
//! and `hmac-sha512`; the client and the mock implement `hmac-sha256`, `hmac-sha384` and
//! `hmac-sha512`, and those three are covered.
#![cfg(feature = "rfc2136")]
// Test code: a failed assumption is a failed test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use secrecy::SecretString;
use zonewright::providers::rfc2136::{Rfc2136, Rfc2136Config, Rfc2136Credentials};
use zonewright::{
    AddOutcome, DeleteOutcome, DomainName, Expect, Provider, RecordData, RecordType, RemoveOutcome,
    RrSet, RrsetTtl, SetOutcome, Txt,
};
use zonewright_mock::rfc2136::{
    BADKEY, BADSIG, CLASS_ANY, CLASS_IN, CLASS_NONE, MockKey, MockRecord, Op, Rfc2136Mock, Seed,
    TYPE_A, TYPE_ANY, TYPE_NS, TYPE_SOA, TYPE_TXT, ZONE,
};

use common::{context, dn};

const NSUPDATE: &str = "/usr/bin/nsupdate";
const DIG: &str = "/usr/bin/dig";

/// The longest a child process may run before it is killed.
const CHILD_DEADLINE: Duration = Duration::from_secs(20);
/// The longest a client operation may take.
const SLOW: Duration = Duration::from_secs(10);

const SOA_TEXT: &str = "ns1.example.org. admin.example.org. 2026111501 7200 3600 1209600 300";

// ---- Child processes ---------------------------------------------------------------------------

struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs `program` with `args`, `stdin` on its standard input; kills it after [`CHILD_DEADLINE`].
fn run(program: &str, args: &[&str], stdin: &str) -> Output {
    assert!(
        Path::new(program).exists(),
        "{program} is required by this test and was not found; install BIND's tools there or \
         leave this ignored test out"
    );
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {program}: {e}"));
    let mut input = child.stdin.take().unwrap();
    let script = stdin.to_owned();
    let writer = std::thread::spawn(move || {
        let _ = input.write_all(script.as_bytes());
    });
    let drain = |mut pipe: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let out = drain(Box::new(child.stdout.take().unwrap()));
    let err = drain(Box::new(child.stderr.take().unwrap()));
    let deadline = Instant::now() + CHILD_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    writer.join().unwrap();
    let stdout = out.join().unwrap();
    let stderr = err.join().unwrap();
    assert!(
        status.is_some(),
        "{program} {args:?} was killed after {CHILD_DEADLINE:?}\nstdout: {stdout}\nstderr: {stderr}"
    );
    Output {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
    }
}

/// A directory under the system's temporary directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "zonewright-rfc2136-interop-{}-{}-{}",
            std::process::id(),
            nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Synthetic key material: splitmix64 over the clock and a counter, different on every run.
fn synthetic_secret(len: usize) -> Vec<u8> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut state = nanos() ^ (u64::from(std::process::id()) << 32);
    state ^= COUNTER
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        out.extend_from_slice(&z.to_be_bytes());
    }
    out.truncate(len);
    out
}

// ---- The lab: the mock, the keys and the tools -------------------------------------------------

#[derive(Clone, Debug)]
struct TestKey {
    /// With the trailing dot.
    name: String,
    /// `hmac-sha256`, `hmac-sha384` or `hmac-sha512`.
    algorithm: &'static str,
    secret: Vec<u8>,
}

impl TestKey {
    fn b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.secret)
    }

    /// The same key name and algorithm with another secret.
    fn with_other_secret(&self) -> TestKey {
        TestKey {
            secret: synthetic_secret(self.secret.len()),
            ..self.clone()
        }
    }

    /// `sha256`, `sha384` or `sha512`, for owner names.
    fn short(&self) -> &'static str {
        self.algorithm.trim_start_matches("hmac-")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    const BOTH: [Transport; 2] = [Transport::Tcp, Transport::Udp];

    fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }

    fn dig_flag(self) -> &'static str {
        match self {
            Transport::Tcp => "+tcp",
            Transport::Udp => "+notcp",
        }
    }
}

/// One record of a `dig` answer.
#[derive(Clone, Debug)]
struct DigRr {
    name: String,
    ttl: u32,
    rtype: String,
    rdata: String,
}

/// What `dig` printed.
#[derive(Debug)]
struct Dig {
    status: String,
    flags: Vec<String>,
    answer: Vec<DigRr>,
    authority: Vec<DigRr>,
    stdout: String,
}

impl Dig {
    /// The RDATA texts of the answer records of `rtype`, sorted.
    fn rdata(&self, rtype: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .answer
            .iter()
            .filter(|r| r.rtype == rtype)
            .map(|r| r.rdata.clone())
            .collect();
        out.sort();
        out
    }
}

struct Lab {
    mock: Rfc2136Mock,
    dir: TempDir,
    sha256: TestKey,
    sha384: TestKey,
    sha512: TestKey,
}

impl Lab {
    async fn start() -> Lab {
        for program in [NSUPDATE, DIG] {
            assert!(
                Path::new(program).exists(),
                "{program} is required by this test and was not found"
            );
        }
        let sha256 = TestKey {
            name: "interop-256.".to_owned(),
            algorithm: "hmac-sha256",
            secret: synthetic_secret(32),
        };
        let sha384 = TestKey {
            name: "interop-384.".to_owned(),
            algorithm: "hmac-sha384",
            secret: synthetic_secret(48),
        };
        let sha512 = TestKey {
            name: "interop-512.".to_owned(),
            algorithm: "hmac-sha512",
            secret: synthetic_secret(64),
        };
        let mut seed = Seed::standard();
        seed.keys = [&sha256, &sha384, &sha512]
            .iter()
            .map(|k| MockKey {
                name: k.name.clone(),
                algorithm: format!("{}.", k.algorithm),
                secret: k.secret.clone(),
            })
            .collect();
        seed.records = vec![
            mock_record(ZONE, RecordType::SOA, 3600, SOA_TEXT),
            mock_record(ZONE, RecordType::NS, 3600, "ns1.example.org."),
        ];
        Lab {
            mock: Rfc2136Mock::start(seed).await,
            dir: TempDir::new(),
            sha256,
            sha384,
            sha512,
        }
    }

    fn keys(&self) -> [&TestKey; 3] {
        [&self.sha256, &self.sha384, &self.sha512]
    }

    fn port(&self) -> String {
        self.mock.addr().port().to_string()
    }

    /// Writes `key` as a `key` statement of named.conf, the form both tools read with `-k`.
    fn key_file(&self, key: &TestKey) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = self.dir.0.join(format!(
            "key-{}.conf",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let text = format!(
            "key \"{}\" {{\n\talgorithm {};\n\tsecret \"{}\";\n}};\n",
            key.name,
            key.algorithm,
            key.b64()
        );
        std::fs::write(&path, text).unwrap();
        path
    }

    /// Runs `nsupdate` with `body` after `server` and `zone example.org.`, then `send`.
    /// `Ok(())` for NOERROR, `Err` with the RCODE `nsupdate` reports otherwise.
    fn nsupdate(&self, key: &TestKey, transport: Transport, body: &str) -> Result<(), String> {
        self.nsupdate_script(key, transport, &format!("zone {ZONE}\n{body}"))
    }

    /// Runs `nsupdate` with `server` then `body`, then `send`.
    fn nsupdate_script(
        &self,
        key: &TestKey,
        transport: Transport,
        body: &str,
    ) -> Result<(), String> {
        let file = self.key_file(key);
        let script = format!(
            "server 127.0.0.1 {}\n{}\nsend\n",
            self.port(),
            body.trim_end()
        );
        // -t: overall timeout; -u, -r: UDP timeout and retries; -v: TCP for the update.
        let mut args = vec![
            "-k",
            file.to_str().unwrap(),
            "-t",
            "5",
            "-u",
            "2",
            "-r",
            "1",
        ];
        if transport == Transport::Tcp {
            args.push("-v");
        }
        let out = tokio::task::block_in_place(|| run(NSUPDATE, &args, &script));
        let failed = out
            .stderr
            .lines()
            .find_map(|l| l.trim().strip_prefix("update failed: "))
            .map(str::to_owned);
        match (out.code, failed) {
            (Some(0), None) => {
                assert!(
                    out.stderr.trim().is_empty(),
                    "nsupdate succeeded with complaints: {}",
                    out.stderr
                );
                Ok(())
            }
            (Some(_), Some(rcode)) => Err(rcode),
            _ => panic!(
                "nsupdate ended unexpectedly ({:?})\nscript:\n{script}\nstdout: {}\nstderr: {}",
                out.code, out.stdout, out.stderr
            ),
        }
    }

    /// Queries `name` and `rtype` with `dig`, signed with `key` (the mock refuses unsigned
    /// queries), without recursion.
    fn dig(&self, key: &TestKey, transport: Transport, name: &str, rtype: &str) -> Dig {
        self.dig_with(key, transport, name, rtype, &[])
    }

    fn dig_with(
        &self,
        key: &TestKey,
        transport: Transport,
        name: &str,
        rtype: &str,
        extra: &[&str],
    ) -> Dig {
        let file = self.key_file(key);
        let port = self.port();
        let mut args = vec![
            "@127.0.0.1",
            "-p",
            &port,
            "-k",
            file.to_str().unwrap(),
            "+norecurse",
            "+time=2",
            "+tries=1",
            "+noall",
            "+comments",
            "+answer",
            "+authority",
            transport.dig_flag(),
        ];
        args.extend_from_slice(extra);
        args.extend([name, rtype]);
        let out = tokio::task::block_in_place(|| run(DIG, &args, ""));
        assert_eq!(
            out.code,
            Some(0),
            "dig {args:?} failed\nstdout: {}\nstderr: {}",
            out.stdout,
            out.stderr
        );
        parse_dig(&out.stdout, &out.stderr)
    }

    fn client(&self, key: &TestKey) -> Rfc2136 {
        let mut settings = Rfc2136Config::new(self.mock.server(), key.name.clone());
        settings.algorithm = key.algorithm.to_owned();
        let credentials = Rfc2136Credentials::new(SecretString::from(key.b64()));
        Rfc2136::new(settings, credentials, &context()).unwrap()
    }
}

/// Parses `dig +noall +comments +answer +authority` output.
fn parse_dig(stdout: &str, stderr: &str) -> Dig {
    let all = format!("{stdout}\n{stderr}");
    assert!(
        !all.contains("Couldn't verify") && !all.contains("TSIG error"),
        "dig could not verify the answer's TSIG:\n{all}"
    );
    let mut dig = Dig {
        status: String::new(),
        flags: Vec::new(),
        answer: Vec::new(),
        authority: Vec::new(),
        stdout: stdout.to_owned(),
    };
    let mut section = "";
    for line in stdout.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.split("status: ").nth(1) {
            dig.status = rest.split(',').next().unwrap_or_default().to_owned();
        } else if let Some(rest) = line.strip_prefix(";; flags:") {
            let flags = rest.split(';').next().unwrap_or_default();
            dig.flags = flags.split_whitespace().map(str::to_owned).collect();
        } else if line.starts_with(";; ANSWER SECTION") {
            section = "answer";
        } else if line.starts_with(";; AUTHORITY SECTION") {
            section = "authority";
        } else if line.starts_with(';') {
            if line.starts_with(";; ") && line.ends_with("SECTION:") {
                section = "";
            }
        } else if !line.trim().is_empty() {
            let rr = parse_dig_rr(line);
            match section {
                "answer" => dig.answer.push(rr),
                "authority" => dig.authority.push(rr),
                _ => panic!("a record outside a known section: {line}\n{stdout}"),
            }
        }
    }
    assert!(!dig.status.is_empty(), "dig printed no status:\n{stdout}");
    dig
}

/// `owner ttl class type rdata...`, separated by whitespace; the RDATA is the rest of the line.
fn parse_dig_rr(line: &str) -> DigRr {
    let mut rest = line;
    let mut fields = Vec::new();
    for _ in 0..4 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        fields.push(&rest[..end]);
        rest = &rest[end..];
    }
    assert_eq!(fields[2], "IN", "class of {line}");
    DigRr {
        name: fields[0].to_ascii_lowercase(),
        ttl: fields[1].parse().unwrap(),
        rtype: fields[3].to_owned(),
        rdata: rest.trim().to_owned(),
    }
}

// ---- TXT presentation, written and read independently of the crate ---------------------------

/// The character-strings as quoted presentation text (RFC 1035 section 5.1): `"` and `\`
/// escaped with a backslash, octets outside 0x20 ..= 0x7E as `\DDD`.
fn txt_presentation(strings: &[&[u8]]) -> String {
    strings
        .iter()
        .map(|s| {
            let mut out = String::from("\"");
            for &b in *s {
                match b {
                    b'"' | b'\\' => {
                        out.push('\\');
                        out.push(char::from(b));
                    }
                    0x20..=0x7e => out.push(char::from(b)),
                    _ => out.push_str(&format!("\\{b:03}")),
                }
            }
            out.push('"');
            out
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The character-strings of quoted presentation text as `dig` prints TXT RDATA.
fn parse_txt_presentation(text: &str) -> Vec<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'"' => {
                i += 1;
                let mut s = Vec::new();
                loop {
                    match bytes.get(i) {
                        None => panic!("unterminated string in {text}"),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            let next = &bytes[i + 1..];
                            if next.len() >= 3 && next[..3].iter().all(u8::is_ascii_digit) {
                                let n = std::str::from_utf8(&next[..3]).unwrap();
                                s.push(n.parse::<u8>().unwrap());
                                i += 4;
                            } else {
                                s.push(next[0]);
                                i += 2;
                            }
                        }
                        Some(&b) => {
                            s.push(b);
                            i += 1;
                        }
                    }
                }
                out.push(s);
            }
            _ => panic!("unquoted TXT data in {text}"),
        }
    }
    out
}

/// TXT RDATA with exactly these character-strings.
fn txt_wire(strings: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in strings {
        out.push(u8::try_from(s.len()).unwrap());
        out.extend_from_slice(s);
    }
    out
}

// ---- Helpers -----------------------------------------------------------------------------------

fn zone() -> DomainName {
    dn("example.org")
}

/// A record as the mock holds it, from presentation text through the crate's parser.
fn mock_record(name: &str, rtype: RecordType, ttl: u32, text: &str) -> MockRecord {
    MockRecord {
        name: name.to_owned(),
        rtype: rtype.code().unwrap(),
        ttl,
        rdata: RecordData::parse(rtype, text)
            .unwrap()
            .to_wire(rtype)
            .unwrap(),
    }
}

/// The RDATA of the mock's records of `name` and `rtype`, sorted.
fn stored(lab: &Lab, name: &str, rtype: u16) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = lab
        .mock
        .control()
        .records_of(name, rtype)
        .into_iter()
        .map(|r| r.rdata)
        .collect();
    out.sort();
    out
}

fn sorted<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v
}

async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(SLOW, f)
        .await
        .expect("the operation is bounded")
}

// ---- nsupdate against the mock -----------------------------------------------------------------

/// With each algorithm and over each transport, `nsupdate` adds a TXT RRset, adds a value to it,
/// deletes one value (class NONE, RFC 2136 section 2.5.4) and deletes the RRset (class ANY,
/// section 2.5.2); after each step the mock holds what RFC 2136 section 3.4.2 says, and `dig`,
/// over TCP and UDP, reads back exactly that. `nsupdate` and `dig` verify the mock's response
/// MACs (RFC 8945 section 5.3) and complain otherwise.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_txt_lifecycle_with_each_algorithm_and_transport() {
    let lab = Lab::start().await;
    for key in lab.keys() {
        for transport in Transport::BOTH {
            let name = format!("life-{}-{}.example.org.", key.short(), transport.label());
            let read = |expected: &[&str]| {
                for via in Transport::BOTH {
                    let dig = lab.dig(key, via, &name, "TXT");
                    let want: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
                    assert_eq!(dig.rdata("TXT"), want, "{name} via {via:?}");
                    assert!(dig.flags.contains(&"aa".to_owned()), "{:?}", dig.flags);
                    if expected.is_empty() {
                        assert_eq!(dig.status, "NXDOMAIN", "{name}");
                        // RFC 2308 section 3: the SOA of the zone in the authority section.
                        assert_eq!(dig.authority.len(), 1, "{}", dig.stdout);
                        assert_eq!(dig.authority[0].rtype, "SOA");
                        assert_eq!(dig.authority[0].ttl, 300);
                    } else {
                        assert_eq!(dig.status, "NOERROR");
                        assert!(dig.answer.iter().all(|r| r.name == name && r.ttl == 300));
                    }
                }
            };
            lab.nsupdate(
                key,
                transport,
                &format!("update add {name} 300 TXT \"one\""),
            )
            .unwrap();
            assert_eq!(stored(&lab, &name, TYPE_TXT), [txt_wire(&[b"one"])]);
            read(&["\"one\""]);
            lab.nsupdate(
                key,
                transport,
                &format!("update add {name} 300 TXT \"two\""),
            )
            .unwrap();
            assert_eq!(
                stored(&lab, &name, TYPE_TXT),
                sorted(vec![txt_wire(&[b"one"]), txt_wire(&[b"two"])])
            );
            read(&["\"one\"", "\"two\""]);
            lab.nsupdate(key, transport, &format!("update delete {name} TXT \"one\""))
                .unwrap();
            assert_eq!(stored(&lab, &name, TYPE_TXT), [txt_wire(&[b"two"])]);
            read(&["\"two\""]);
            lab.nsupdate(
                key,
                transport,
                &format!("update add {name} 300 TXT \"three\""),
            )
            .unwrap();
            lab.nsupdate(key, transport, &format!("update delete {name} TXT"))
                .unwrap();
            assert!(stored(&lab, &name, TYPE_TXT).is_empty());
            read(&[]);
        }
    }
    // What nsupdate sent is what RFC 2136 section 2.5 describes.
    let updates: Vec<_> = lab
        .mock
        .control()
        .calls()
        .into_iter()
        .filter(|c| c.op == Op::Update)
        .flat_map(|c| c.updates)
        .collect();
    let one = txt_wire(&[b"one"]);
    assert!(
        updates
            .iter()
            .any(|u| u.class == CLASS_IN && u.ttl == 300 && u.rdata == one)
    );
    assert!(
        updates
            .iter()
            .any(|u| u.class == CLASS_NONE && u.ttl == 0 && u.rtype == TYPE_TXT && u.rdata == one)
    );
    assert!(
        updates.iter().any(|u| u.class == CLASS_ANY
            && u.ttl == 0
            && u.rtype == TYPE_TXT
            && u.rdata.is_empty())
    );
}

/// Every prerequisite form `nsupdate` offers is encoded as RFC 2136 section 2.4 says, and the
/// mock's verdicts are those of section 3.2 under the RCODE names `nsupdate` prints. An update
/// whose prerequisites fail changes nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_prerequisites_succeed_and_fail_as_rfc_2136_says() {
    type Encoded<'a> = &'a [(u16, u16, &'a [u8])];
    let lab = Lab::start().await;
    let key = &lab.sha256;
    let pre = "pre.example.org.";
    lab.nsupdate(
        key,
        Transport::Tcp,
        &format!("update add {pre} 300 TXT \"x\"\nupdate add {pre} 300 TXT \"y\""),
    )
    .unwrap();
    let free = "free.example.org.";
    let cases: &[(&str, Option<&str>, Encoded<'_>)] = &[
        (
            "prereq nxrrset pre.example.org. TXT",
            Some("YXRRSET"),
            &[(CLASS_NONE, TYPE_TXT, b"")],
        ),
        (
            "prereq nxrrset pre.example.org. A",
            None,
            &[(CLASS_NONE, TYPE_A, b"")],
        ),
        (
            "prereq yxrrset pre.example.org. TXT",
            None,
            &[(CLASS_ANY, TYPE_TXT, b"")],
        ),
        (
            "prereq yxrrset pre.example.org. A",
            Some("NXRRSET"),
            &[(CLASS_ANY, TYPE_A, b"")],
        ),
        // Value dependent: the RRset must match exactly (section 3.2.3).
        (
            "prereq yxrrset pre.example.org. TXT \"x\"",
            Some("NXRRSET"),
            &[(CLASS_IN, TYPE_TXT, b"\x01x")],
        ),
        (
            "prereq yxrrset pre.example.org. TXT \"y\"\n\
             prereq yxrrset pre.example.org. TXT \"x\"",
            None,
            &[
                (CLASS_IN, TYPE_TXT, b"\x01y"),
                (CLASS_IN, TYPE_TXT, b"\x01x"),
            ],
        ),
        (
            "prereq yxrrset pre.example.org. TXT \"x\"\n\
             prereq yxrrset pre.example.org. TXT \"y\"\n\
             prereq yxrrset pre.example.org. TXT \"z\"",
            Some("NXRRSET"),
            &[
                (CLASS_IN, TYPE_TXT, b"\x01x"),
                (CLASS_IN, TYPE_TXT, b"\x01y"),
                (CLASS_IN, TYPE_TXT, b"\x01z"),
            ],
        ),
        (
            "prereq nxdomain pre.example.org.",
            Some("YXDOMAIN"),
            &[(CLASS_NONE, TYPE_ANY, b"")],
        ),
        (
            "prereq nxdomain free.example.org.",
            None,
            &[(CLASS_NONE, TYPE_ANY, b"")],
        ),
        (
            "prereq yxdomain pre.example.org.",
            None,
            &[(CLASS_ANY, TYPE_ANY, b"")],
        ),
        (
            "prereq yxdomain free.example.org.",
            Some("NXDOMAIN"),
            &[(CLASS_ANY, TYPE_ANY, b"")],
        ),
        // In order: the first failing prerequisite decides (section 3.2.5).
        (
            "prereq nxrrset pre.example.org. TXT\nprereq nxdomain pre.example.org.",
            Some("YXRRSET"),
            &[(CLASS_NONE, TYPE_TXT, b""), (CLASS_NONE, TYPE_ANY, b"")],
        ),
        (
            "prereq nxdomain pre.example.org.\nprereq nxrrset pre.example.org. TXT",
            Some("YXDOMAIN"),
            &[(CLASS_NONE, TYPE_ANY, b""), (CLASS_NONE, TYPE_TXT, b"")],
        ),
        // A prerequisite outside the zone (section 3.2.5: NOTZONE).
        (
            "prereq yxdomain pre.example.net.",
            Some("NOTZONE"),
            &[(CLASS_ANY, TYPE_ANY, b"")],
        ),
    ];
    for (i, (prereqs, expected, encoded)) in cases.iter().enumerate() {
        for transport in Transport::BOTH {
            let marker = format!("marker-{i}-{}.example.org.", transport.label());
            lab.mock.control().clear_calls();
            let result = lab.nsupdate(
                key,
                transport,
                &format!("{prereqs}\nupdate add {marker} 60 TXT \"m\""),
            );
            assert_eq!(
                result.err().as_deref(),
                *expected,
                "{prereqs} over {transport:?}"
            );
            assert_eq!(
                lab.mock.control().records(&marker).len(),
                usize::from(expected.is_none()),
                "{prereqs}: applied only when every prerequisite holds"
            );
            let calls = lab.mock.control().calls();
            let update = calls.iter().find(|c| c.op == Op::Update).unwrap();
            let got: Vec<(u16, u16, Vec<u8>, u32)> = update
                .prereqs
                .iter()
                .map(|p| (p.class, p.rtype, p.rdata.clone(), p.ttl))
                .collect();
            let want: Vec<(u16, u16, Vec<u8>, u32)> = encoded
                .iter()
                .map(|(c, t, r)| (*c, *t, r.to_vec(), 0))
                .collect();
            assert_eq!(got, want, "{prereqs}: the encoding of section 2.4");
        }
    }
    assert_eq!(
        stored(&lab, pre, TYPE_TXT),
        sorted(vec![txt_wire(&[b"x"]), txt_wire(&[b"y"])])
    );
    assert!(lab.mock.control().records(free).is_empty());
}

/// A wrong secret is NOTAUTH with TSIG error BADSIG, an unknown key name and a known name with
/// another algorithm are NOTAUTH with BADKEY (RFC 8945 sections 5.2.1 and 5.2.2; 5.3.2: no MAC
/// in the answer, which both tools accept as such); none of them changes anything, and `dig`
/// gets NOTAUTH for a query.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_with_a_bad_key_is_refused_and_changes_nothing() {
    let lab = Lab::start().await;
    let before = lab.mock.control().all_records();
    let unknown = TestKey {
        name: "no-such-key.".to_owned(),
        ..lab.sha256.clone()
    };
    let other_algorithm = TestKey {
        algorithm: "hmac-sha512",
        ..lab.sha256.clone()
    };
    let cases = [
        (lab.sha256.with_other_secret(), "NOTAUTH(BADSIG)", BADSIG),
        (lab.sha384.with_other_secret(), "NOTAUTH(BADSIG)", BADSIG),
        (lab.sha512.with_other_secret(), "NOTAUTH(BADSIG)", BADSIG),
        (unknown, "NOTAUTH(BADKEY)", BADKEY),
        (other_algorithm, "NOTAUTH(BADKEY)", BADKEY),
    ];
    for (key, rcode, tsig_error) in &cases {
        for transport in Transport::BOTH {
            lab.mock.control().clear_calls();
            let result = lab.nsupdate(
                key,
                transport,
                "update add bad.example.org. 60 TXT \"never\"",
            );
            assert_eq!(result.err().as_deref(), Some(*rcode), "{key:?}");
            let calls = lab.mock.control().calls();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].tsig_error, *tsig_error);
            assert_eq!(lab.mock.control().all_records(), before);

            let file = lab.key_file(key);
            let port = lab.port();
            let args = [
                "@127.0.0.1",
                "-p",
                &port,
                "-k",
                file.to_str().unwrap(),
                "+norecurse",
                "+time=2",
                "+tries=1",
                transport.dig_flag(),
                "example.org.",
                "SOA",
            ];
            let out = tokio::task::block_in_place(|| run(DIG, &args, ""));
            assert!(
                out.stdout.contains("status: NOTAUTH"),
                "{key:?}: {}",
                out.stdout
            );
            assert!(
                out.stdout.contains("ANSWER: 0"),
                "no answer behind a TSIG failure: {}",
                out.stdout
            );
        }
    }
}

/// An update of a name outside the zone section's zone is NOTZONE (RFC 2136 section 3.4.1.3)
/// and a zone the server does not serve is NOTAUTH (section 3.1.2); neither changes anything.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_outside_the_zone_is_notzone() {
    let lab = Lab::start().await;
    let before = lab.mock.control().all_records();
    for key in lab.keys() {
        for transport in Transport::BOTH {
            let result = lab.nsupdate(
                key,
                transport,
                "update add elsewhere.example.net. 60 TXT \"never\"",
            );
            assert_eq!(result.err().as_deref(), Some("NOTZONE"));
            // The parent of the apex is outside the zone as well.
            let result = lab.nsupdate(key, transport, "update add org. 60 TXT \"never\"");
            assert_eq!(result.err().as_deref(), Some("NOTZONE"));
            let result = lab.nsupdate_script(
                key,
                transport,
                "zone example.net.\nupdate add a.example.net. 60 TXT \"never\"",
            );
            assert_eq!(result.err().as_deref(), Some("NOTAUTH"));
            assert_eq!(lab.mock.control().all_records(), before);
        }
    }
}

/// Without a `zone` statement `nsupdate` finds the zone itself with an SOA query for the name.
/// The mock's negative answer carries the zone's SOA in the authority section (RFC 2308 section
/// 3), which `nsupdate` takes as the zone, so it needs a single query.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_finds_the_zone_from_the_negative_answer() {
    let lab = Lab::start().await;
    let name = "deep.new.example.org.";
    let dig = lab.dig(&lab.sha256, Transport::Udp, name, "SOA");
    assert_eq!(dig.status, "NXDOMAIN");
    assert!(dig.answer.is_empty());
    assert_eq!(dig.authority.len(), 1, "{}", dig.stdout);
    assert_eq!(dig.authority[0].name, ZONE);
    // The lower of the SOA's TTL (3600) and its MINIMUM (300), RFC 2308 section 3.
    assert_eq!(dig.authority[0].ttl, 300);
    let dig = lab.dig(&lab.sha256, Transport::Tcp, ZONE, "TXT");
    assert_eq!((dig.status.as_str(), dig.answer.len()), ("NOERROR", 0));
    assert_eq!(dig.authority[0].rtype, "SOA", "no data: SOA as well");

    for transport in Transport::BOTH {
        lab.mock.control().clear_calls();
        lab.nsupdate_script(
            &lab.sha512,
            transport,
            &format!("update add {name} 60 TXT \"found\""),
        )
        .unwrap();
        let calls = lab.mock.control().calls();
        let queries: Vec<_> = calls.iter().filter(|c| c.op == Op::Query).collect();
        assert_eq!(queries.len(), 1, "{calls:?}");
        assert_eq!(
            (queries[0].qname.as_str(), queries[0].qtype),
            (name, TYPE_SOA)
        );
        let update = calls.iter().find(|c| c.op == Op::Update).unwrap();
        assert_eq!(update.qname, ZONE);
        assert_eq!(lab.mock.control().txt(name), ["found"]);
        lab.nsupdate(&lab.sha512, transport, &format!("update delete {name}"))
            .unwrap();
    }
    // The apex keeps its SOA and NS (RFC 2136 section 3.4.2.3) through nsupdate's deletion of
    // every RRset of the name.
    lab.nsupdate(
        &lab.sha256,
        Transport::Tcp,
        &format!("update delete {ZONE}"),
    )
    .unwrap();
    assert_eq!(lab.mock.control().records_of(ZONE, TYPE_SOA).len(), 1);
    assert_eq!(lab.mock.control().records_of(ZONE, TYPE_NS).len(), 1);
}

// ---- Awkward TXT values ------------------------------------------------------------------------

/// TXT values as lists of character-strings: spaces, quotes and backslashes, octets outside
/// printable ASCII, a 255-octet string, an empty string and several strings in one RDATA.
fn awkward_values() -> Vec<Vec<Vec<u8>>> {
    vec![
        vec![b"with spaces inside".to_vec()],
        vec![b"quote \" and backslash \\ and semicolon ;".to_vec()],
        vec![b"caf\xc3\xa9 \x01 tab\t".to_vec()],
        vec![vec![b'a'; 255]],
        vec![Vec::new()],
        vec![
            b"first".to_vec(),
            b"second part".to_vec(),
            b"third".to_vec(),
        ],
        vec![vec![b'b'; 255], b"tail".to_vec()],
    ]
}

/// `nsupdate` writes each awkward value; the mock stores exactly the RDATA of RFC 1035 section
/// 3.3.14 (string boundaries included), `dig` reads the same character-strings over TCP and UDP,
/// and the client reads the same data.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn awkward_txt_values_written_by_nsupdate_read_back_identical() {
    let lab = Lab::start().await;
    let key = &lab.sha512;
    let client = lab.client(key);
    for (i, value) in awkward_values().iter().enumerate() {
        let strings: Vec<&[u8]> = value.iter().map(Vec::as_slice).collect();
        let name = format!("awkward-{i}.example.org.");
        let text = txt_presentation(&strings);
        lab.nsupdate(
            key,
            Transport::Tcp,
            &format!("update add {name} 300 TXT {text}"),
        )
        .unwrap();
        let wire = txt_wire(&strings);
        assert_eq!(
            stored(&lab, &name, TYPE_TXT),
            std::slice::from_ref(&wire),
            "{text}"
        );
        for transport in Transport::BOTH {
            let dig = lab.dig(key, transport, &name, "TXT");
            let read = dig.rdata("TXT");
            assert_eq!(read.len(), 1, "{}", dig.stdout);
            assert_eq!(
                parse_txt_presentation(&read[0]),
                *value,
                "{text} via {transport:?}"
            );
        }
        let got = bounded(client.get_rrset(&zone(), &dn(&name), RecordType::TXT))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.ttl(), Some(RrsetTtl::from_secs(300).unwrap()));
        assert_eq!(
            got.records(),
            [RecordData::from_wire(RecordType::TXT, &wire).unwrap()]
        );
        // The crate's TXT value is the concatenation of the strings (design section 4.4).
        let data = Txt::from_data(&got.records()[0]).unwrap();
        assert_eq!(data.as_bytes(), value.concat().as_slice());
    }
}

/// An answer longer than 512 octets over UDP is cut with TC set and still signed (RFC 1035
/// section 4.2.1, RFC 2181 section 9); `dig` verifies it and retries over TCP, where it gets the
/// whole RRset.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn long_udp_answer_is_truncated_and_dig_retries_over_tcp() {
    let lab = Lab::start().await;
    let key = &lab.sha256;
    let name = "long.example.org.";
    let values: Vec<Vec<u8>> = (b'c'..=b'f').map(|c| vec![c; 200]).collect();
    let body: Vec<String> = values
        .iter()
        .map(|v| format!("update add {name} 300 TXT {}", txt_presentation(&[v])))
        .collect();
    lab.nsupdate(key, Transport::Udp, &body.join("\n")).unwrap();
    assert_eq!(stored(&lab, name, TYPE_TXT).len(), 4);
    let cut = lab.dig_with(key, Transport::Udp, name, "TXT", &["+ignore"]);
    assert!(cut.flags.contains(&"tc".to_owned()), "{}", cut.stdout);
    assert!(cut.answer.is_empty());
    let full = lab.dig(key, Transport::Udp, name, "TXT");
    assert!(
        full.stdout.contains("retrying in TCP mode"),
        "{}",
        full.stdout
    );
    let read: Vec<Vec<Vec<u8>>> = full
        .rdata("TXT")
        .iter()
        .map(|t| parse_txt_presentation(t))
        .collect();
    let want: Vec<Vec<Vec<u8>>> = values.iter().map(|v| vec![v.clone()]).collect();
    assert_eq!(read, want);
}

// ---- Cross direction: the client and the tools -------------------------------------------------

/// What the client writes, `dig` reads, and `nsupdate`'s value-dependent prerequisite (RFC 2136
/// section 3.2.3, an exact RDATA match on the server) accepts as the RRset the client wrote.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn client_writes_and_the_tools_read_the_same_rrset() {
    let lab = Lab::start().await;
    for key in lab.keys() {
        let client = lab.client(key);
        let name = format!("_acme-challenge.{}.example.org.", key.short());
        let owner = dn(&name);
        let v1 = Txt::new("token-one_-AZaz09").unwrap();
        let v2 = Txt::new("token-two").unwrap();
        assert_eq!(
            bounded(client.add_txt_value(&zone(), &owner, &v1, None))
                .await
                .unwrap(),
            AddOutcome::Created
        );
        assert_eq!(
            bounded(client.add_txt_value(&zone(), &owner, &v2, None))
                .await
                .unwrap(),
            AddOutcome::Appended
        );
        for transport in Transport::BOTH {
            let dig = lab.dig(key, transport, &name, "TXT");
            assert_eq!(dig.rdata("TXT"), ["\"token-one_-AZaz09\"", "\"token-two\""]);
            // The client's default TTL setting (60).
            assert!(dig.answer.iter().all(|r| r.ttl == 60));
        }
        lab.nsupdate(
            key,
            Transport::Tcp,
            &format!(
                "prereq yxrrset {name} TXT \"token-two\"\n\
                 prereq yxrrset {name} TXT \"token-one_-AZaz09\"\n\
                 update add marker.{name} 60 TXT \"m\""
            ),
        )
        .unwrap();
        assert_eq!(
            bounded(client.remove_txt_value(&zone(), &owner, &v1))
                .await
                .unwrap(),
            RemoveOutcome::Removed
        );
        assert_eq!(
            lab.dig(key, Transport::Udp, &name, "TXT").rdata("TXT"),
            ["\"token-two\""]
        );

        // Record level: awkward TXT data and an A RRset.
        let txt_name = format!("set.{}.example.org.", key.short());
        let datas: Vec<RecordData> = [
            b"with \"quotes\" and \\ ".to_vec(),
            vec![b'q'; 300],
            b"caf\xc3\xa9".to_vec(),
        ]
        .into_iter()
        .map(|d| Txt::new(d).unwrap().to_data().unwrap())
        .collect();
        let set = RrSet::new(
            dn(&txt_name),
            RecordType::TXT,
            Some(RrsetTtl::from_secs(120).unwrap()),
            datas,
        )
        .unwrap();
        assert_eq!(
            bounded(client.set_rrset(&zone(), &set, Expect::Absent))
                .await
                .unwrap(),
            SetOutcome::Created
        );
        let dig = lab.dig(key, Transport::Tcp, &txt_name, "TXT");
        let mut read: Vec<Vec<Vec<u8>>> = dig
            .rdata("TXT")
            .iter()
            .map(|t| parse_txt_presentation(t))
            .collect();
        read.sort();
        // The client cuts data into 255-octet character-strings (design section 4.4).
        let mut want = vec![
            vec![b"with \"quotes\" and \\ ".to_vec()],
            vec![vec![b'q'; 255], vec![b'q'; 45]],
            vec![b"caf\xc3\xa9".to_vec()],
        ];
        want.sort();
        assert_eq!(read, want);
        assert!(dig.answer.iter().all(|r| r.ttl == 120));

        let a_name = format!("host.{}.example.org.", key.short());
        let a = RrSet::new(
            dn(&a_name),
            RecordType::A,
            None,
            ["192.0.2.1", "192.0.2.10"].map(|t| RecordData::parse(RecordType::A, t).unwrap()),
        )
        .unwrap();
        bounded(client.set_rrset(&zone(), &a, Expect::Any))
            .await
            .unwrap();
        for transport in Transport::BOTH {
            assert_eq!(
                lab.dig(key, transport, &a_name, "A").rdata("A"),
                ["192.0.2.1", "192.0.2.10"]
            );
        }
        lab.nsupdate(
            key,
            Transport::Udp,
            &format!(
                "prereq yxrrset {a_name} A 192.0.2.10\n\
                 prereq yxrrset {a_name} A 192.0.2.1\n\
                 update delete {a_name} A"
            ),
        )
        .unwrap();
        assert!(
            bounded(client.get_rrset(&zone(), &dn(&a_name), RecordType::A))
                .await
                .unwrap()
                .is_none()
        );
    }
}

/// What `nsupdate` writes, the client reads (`get_rrset`) as the same RRset with the same TTL,
/// and `dig`'s view, parsed by the crate, is the same set. The client then replaces and deletes
/// it under `Expect::Matches` of what it read, which works only if the RDATA of the client's
/// value-dependent prerequisite equals what `nsupdate` wrote.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn nsupdate_writes_and_the_client_reads_the_same_rrset() {
    let lab = Lab::start().await;
    for key in lab.keys() {
        let client = lab.client(key);
        let base = format!("{}.example.org.", key.short());
        let cases: &[(&str, RecordType, &[&str])] = &[
            (
                "txt",
                RecordType::TXT,
                &["\"plain\"", "\"with space\"", "\"q\\\"uote\""],
            ),
            ("a", RecordType::A, &["192.0.2.7", "198.51.100.1"]),
            ("aaaa", RecordType::AAAA, &["2001:db8::1"]),
            (
                "mx",
                RecordType::MX,
                &["10 mail.example.org.", "20 backup.example.net."],
            ),
            ("cname", RecordType::CNAME, &["target.example.net."]),
            ("srv", RecordType::SRV, &["0 5 5060 sip.example.org."]),
            ("caa", RecordType::CAA, &["0 issue \"ca.example.net\""]),
        ];
        for (label, rtype, texts) in cases {
            let name = format!("{label}.{base}");
            let type_text = rtype.to_string();
            let body: Vec<String> = texts
                .iter()
                .map(|t| format!("update add {name} 3600 {type_text} {t}"))
                .collect();
            lab.nsupdate(key, Transport::Udp, &body.join("\n")).unwrap();
            let read = bounded(client.get_rrset(&zone(), &dn(&name), *rtype))
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{name} {type_text}: nothing read"));
            let want = RrSet::new(
                dn(&name),
                *rtype,
                Some(RrsetTtl::from_secs(3600).unwrap()),
                texts.iter().map(|t| RecordData::parse(*rtype, t).unwrap()),
            )
            .unwrap();
            assert!(read.same_records(&want), "{name}: {read:?} vs {want:?}");
            assert_eq!(read.ttl(), want.ttl());
            let dig = lab.dig(key, Transport::Tcp, &name, &type_text);
            let seen = RrSet::new(
                dn(&name),
                *rtype,
                None,
                dig.rdata(&type_text)
                    .iter()
                    .map(|t| RecordData::parse(*rtype, t).unwrap()),
            )
            .unwrap();
            assert!(seen.same_records(&want), "{name}: dig saw {seen:?}");

            let replaced = want
                .clone()
                .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()));
            assert_eq!(
                bounded(client.set_rrset(&zone(), &replaced, Expect::Matches(&read)))
                    .await
                    .unwrap(),
                SetOutcome::Replaced,
                "{name}"
            );
            let dig = lab.dig(key, Transport::Udp, &name, &type_text);
            assert!(!dig.answer.is_empty() && dig.answer.iter().all(|r| r.ttl == 600));
            let read = bounded(client.get_rrset(&zone(), &dn(&name), *rtype))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                bounded(client.delete_rrset(&zone(), &dn(&name), *rtype, Expect::Matches(&read)))
                    .await
                    .unwrap(),
                DeleteOutcome::Deleted,
                "{name}"
            );
            assert!(
                lab.dig(key, Transport::Tcp, &name, &type_text)
                    .answer
                    .is_empty()
            );
        }
    }
}

/// A TXT value that `nsupdate` wrote as several character-strings is one value to the client
/// (design section 4.4), yet the client's deletions and prerequisites carry the RDATA exactly as
/// the server holds it, which is what RFC 2136 sections 3.2.3 and 3.4.2.4 match against: the
/// client removes the value, and its conditional writes against what it read go through.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs BIND nsupdate and dig at /usr/bin; run with --ignored"]
async fn client_handles_multi_string_values_written_by_nsupdate() {
    let lab = Lab::start().await;
    let key = &lab.sha256;
    let client = lab.client(key);
    let name = "multi.example.org.";
    let owner = dn(name);
    let split = txt_wire(&[b"a", b"b"]);
    let other = txt_wire(&[b"other"]);
    let write = |lab: &Lab| {
        lab.nsupdate(
            key,
            Transport::Tcp,
            &format!("update add {name} 300 TXT \"a\" \"b\"\nupdate add {name} 300 TXT \"other\""),
        )
        .unwrap();
        assert_eq!(
            stored(lab, name, TYPE_TXT),
            sorted(vec![split.clone(), other.clone()])
        );
    };
    write(&lab);
    let read = bounded(client.get_rrset(&zone(), &owner, RecordType::TXT))
        .await
        .unwrap()
        .unwrap();
    let ab = Txt::new("ab").unwrap();
    assert!(read.contains(&ab.to_data().unwrap()));
    assert_eq!(
        bounded(client.remove_txt_value(&zone(), &owner, &ab))
            .await
            .unwrap(),
        RemoveOutcome::Removed
    );
    assert_eq!(stored(&lab, name, TYPE_TXT), std::slice::from_ref(&other));

    lab.nsupdate(key, Transport::Tcp, &format!("update delete {name} TXT"))
        .unwrap();
    write(&lab);
    let read = bounded(client.get_rrset(&zone(), &owner, RecordType::TXT))
        .await
        .unwrap()
        .unwrap();
    let longer = read
        .clone()
        .with_ttl(Some(RrsetTtl::from_secs(600).unwrap()));
    assert_eq!(
        bounded(client.set_rrset(&zone(), &longer, Expect::Matches(&read)))
            .await
            .unwrap(),
        SetOutcome::Replaced
    );
    // The data did not change, so the RDATA stays as the server held it; the TTL changed.
    assert_eq!(
        stored(&lab, name, TYPE_TXT),
        sorted(vec![split.clone(), other.clone()])
    );
    assert!(
        lab.mock
            .control()
            .records_of(name, TYPE_TXT)
            .iter()
            .all(|r| r.ttl == 600)
    );
    lab.nsupdate(key, Transport::Tcp, &format!("update delete {name} TXT"))
        .unwrap();
    write(&lab);
    let read = bounded(client.get_rrset(&zone(), &owner, RecordType::TXT))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bounded(client.delete_rrset(&zone(), &owner, RecordType::TXT, Expect::Matches(&read)))
            .await
            .unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(stored(&lab, name, TYPE_TXT).is_empty());
}
