//! DNS over TCP with TSIG: one signed exchange per attempt, with bounded repeats.
//!
//! - Framing: a two-octet length before each message (RFC 1035 section 4.2.2; RFC 7766 section
//!   8). One new connection per attempt; the connection is closed after the answer.
//! - Timeouts (design section 11.3): `ContextOptions::connect_timeout` covers name resolution and
//!   the TCP connect, `ContextOptions::request_timeout` one exchange from sending the request to
//!   having read the whole answer. A length prefix below the size of a DNS header is refused;
//!   the framing itself bounds an answer at 65535 octets.
//! - Every request is signed and every answer verified (RFC 8945 sections 5.1 and 5.4): its ID,
//!   QR bit, opcode and question or zone section must match the request, and its TSIG must
//!   verify against the request MAC. An answer that is not signed with the key is
//!   `Error::Protocol` whatever its RCODE, so a forged answer can neither report success nor turn
//!   a removal into "not present". TSIG errors reported by the server (NOTAUTH with BADKEY,
//!   BADSIG, BADTIME, BADTRUNC; RFC 8945 section 5.2) are `Error::Auth`.
//! - Repeats (design sections 5.3 and 11.3): every message this client sends is idempotent at
//!   the server — a query, an empty update with a prerequisite, the addition of one RR (a
//!   duplicate "will be silently ignored", RFC 2136 section 2.5.1) and the deletion of one RR
//!   ("If no such RRs exist, then this Update RR will be silently ignored", section 2.5.4). So
//!   a connection failure, a timeout, an answer cut short and SERVFAIL are repeated, up to 3
//!   attempts with the back-off of section 5.3 and a new message ID and signature each time
//!   (RFC 8945 section 5.4.2 suggests a new ID for a repeat). Everything else is not repeated.
//! - Tracing: one `DEBUG` event per attempt, target `zonewright::rfc2136`, with the operation,
//!   the RCODE when an answer was read, and the duration. No message content, no key, no MAC.

use std::io::ErrorKind as IoErrorKind;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};

use crate::context::Context;
use crate::error::Error;
use crate::redact::Detail;

use super::config::Server;
use super::tsig::{self, Key, Verdict};
use super::wire::{self, HEADER_LEN, OPCODE_UPDATE, Request, Response, rcode};

/// Target of the client's `tracing` events.
const TARGET: &str = "zonewright::rfc2136";

/// Attempts per message, counting the first (design section 5.3).
const MAX_ATTEMPTS: u32 = 3;

/// Back-off step before attempt `n + 1`: `500 ms × n`, plus up to 25 % (design section 5.3).
const BACKOFF_STEP_MS: u64 = 500;

fn transient(text: &'static str) -> Error {
    Error::Transient {
        detail: Detail::constant(text),
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// A verified answer.
#[derive(Debug)]
pub(super) struct Answer {
    /// The parsed answer.
    pub(super) response: Response,
    /// The answer as received; record RDATA ranges point into it.
    pub(super) buf: Vec<u8>,
}

impl Answer {
    pub(super) fn rcode(&self) -> u8 {
        self.response.rcode()
    }

    /// The RDATA of `record`.
    pub(super) fn rdata(&self, record: &wire::Record) -> Option<&[u8]> {
        self.buf.get(record.rdata.clone())
    }
}

/// The connection settings and the key.
#[derive(Debug)]
pub(super) struct Transport {
    server: Server,
    key: Key,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl Transport {
    pub(super) fn new(server: Server, key: Key, ctx: &Context) -> Transport {
        let options = ctx.options();
        Transport {
            server,
            key,
            connect_timeout: options.connect_timeout,
            request_timeout: options.request_timeout,
        }
    }

    /// Sends `request` and returns the verified answer, repeating as the module documentation
    /// describes. `op` names the operation in the `tracing` event. A final SERVFAIL is returned
    /// as an answer; the caller maps it.
    pub(super) async fn exchange(
        &self,
        request: &Request,
        op: &'static str,
    ) -> Result<Answer, Error> {
        let mut attempt = 1;
        loop {
            let started = Instant::now();
            let result = self.exchange_once(request).await;
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match &result {
                Ok(answer) => tracing::debug!(
                    target: TARGET,
                    op,
                    rcode = answer.rcode(),
                    elapsed_ms,
                    "provider request"
                ),
                Err(_) => tracing::debug!(target: TARGET, op, elapsed_ms, "provider request"),
            }
            let repeat = match &result {
                Err(Error::Transient { .. }) => true,
                Ok(answer) => answer.rcode() == rcode::SERVFAIL,
                Err(_) => false,
            };
            if !repeat || attempt >= MAX_ATTEMPTS {
                return result;
            }
            tokio::time::sleep(backoff(attempt)).await;
            attempt += 1;
        }
    }

    async fn exchange_once(&self, request: &Request) -> Result<Answer, Error> {
        let id = fastrand::u16(..);
        let mut message = request.with_id(id);
        let request_mac = tsig::sign(&mut message, &self.key, unix_now()?)?;
        let buf = self.round_trip(&message).await?;
        let response = wire::parse(&buf)
            .map_err(|_| protocol("the answer is not a well-formed DNS message"))?;
        if response.id != id || !response.is_response() || response.opcode() != request.opcode {
            return Err(protocol("the answer does not match the request"));
        }
        match tsig::verify(&buf, &response, &request_mac, &self.key, unix_now()?) {
            Verdict::Ok => {}
            Verdict::Unsigned => {
                return Err(protocol(
                    "the answer to a signed request is not signed (RFC 8945 section 5.4)",
                ));
            }
            Verdict::Invalid(why) => return Err(protocol(why)),
            // RFC 8945 section 5.2: every TSIG error is answered with RCODE NOTAUTH.
            Verdict::ServerError(error) if response.rcode() == rcode::NOTAUTH => {
                return Err(Error::Auth {
                    detail: Detail::constant(tsig::error_text(error)),
                });
            }
            Verdict::ServerError(_) => {
                return Err(protocol(
                    "the answer reports a TSIG error with an RCODE other than NOTAUTH",
                ));
            }
        }
        if response.truncated() {
            return Err(protocol(
                "the answer is marked truncated, which TCP does not allow",
            ));
        }
        // The question or zone section must repeat the request's. An UPDATE answer may leave it
        // empty (RFC 2136 section 3.8: the server may place zeros in the count fields).
        let echoed = match response.questions.as_slice() {
            [] => request.opcode == OPCODE_UPDATE,
            [question] => *question == request.question,
            _ => false,
        };
        if !echoed {
            return Err(protocol(
                "the answer does not repeat the question of the request",
            ));
        }
        Ok(Answer { response, buf })
    }

    /// Connects, writes the framed message and reads the framed answer.
    async fn round_trip(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut stream = match timeout(self.connect_timeout, self.connect()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(transient("connecting to the DNS server timed out")),
        };
        let exchange = async {
            let len = u16::try_from(message.len()).map_err(|_| Error::InvalidInput {
                detail: Detail::constant("the signed DNS message would exceed 65535 octets"),
            })?;
            let mut framed = Vec::with_capacity(message.len() + 2);
            framed.extend_from_slice(&len.to_be_bytes());
            framed.extend_from_slice(message);
            stream.write_all(&framed).await.map_err(io_error)?;
            let len = usize::from(stream.read_u16().await.map_err(io_error)?);
            if len < HEADER_LEN {
                return Err(protocol("the answer is shorter than a DNS header"));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.map_err(io_error)?;
            Ok(buf)
        };
        match timeout(self.request_timeout, exchange).await {
            Ok(result) => result,
            Err(_) => Err(transient("the DNS server did not answer in time")),
        }
    }

    async fn connect(&self) -> Result<TcpStream, Error> {
        let failed = || transient("could not connect to the DNS server");
        match &self.server {
            Server::Addr(addr) => TcpStream::connect(addr).await.map_err(|_| failed()),
            Server::Host { host, port } => {
                let addrs = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|_| transient("could not resolve the DNS server's name"))?;
                for addr in addrs {
                    if let Ok(stream) = TcpStream::connect(addr).await {
                        return Ok(stream);
                    }
                }
                Err(failed())
            }
        }
    }
}

fn io_error(e: std::io::Error) -> Error {
    if e.kind() == IoErrorKind::UnexpectedEof {
        transient("the DNS server closed the connection before the answer was complete")
    } else {
        transient("the connection to the DNS server failed")
    }
}

/// The Unix time in seconds (RFC 8945 section 4.2: "seconds since 00:00 on 1970-01-01 UTC,
/// ignoring leap seconds").
fn unix_now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| protocol("the system clock is set before 1970"))
}

fn backoff(attempt: u32) -> Duration {
    let base = BACKOFF_STEP_MS.saturating_mul(u64::from(attempt));
    Duration::from_millis(base.saturating_add(fastrand::u64(0..=base / 4)))
}
