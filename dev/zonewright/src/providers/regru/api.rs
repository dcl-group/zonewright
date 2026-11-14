//! The reg.ru API 2 as this client uses it: one function per API function, the wire types and the
//! classification of answers. Nothing here knows the value layer or the record layer; `client.rs`,
//! `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - The reg.ru API 2 documentation, <https://www.reg.ru/reseller/api2doc> ("the documentation",
//!   section numbers below are its own; it is written in Russian):
//!   - 1.2: a limit of 1200 requests per hour for a client and for an IP address, at once; the
//!     error codes `IP_EXCEEDED_ALLOWED_CONNECTION_RATE` and
//!     `ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE`;
//!   - 2.2.2 and 2.2.3.2: parameters are sent as an `application/x-www-form-urlencoded` `POST`
//!     body; structured parameters as JSON in the field `input_data` with `input_format=json`;
//!   - 2.2.4.1 and 2.2.4.2: authentication by the form fields `username` and `password`, which
//!     "must not be passed inside `input_data`"; `output_content_type` sets the content type of
//!     the answer; the default output format is JSON;
//!   - 2.3.2: every answer has `result` (`success` or `error`); an error has `error_code` and
//!     `error_text`; functions that work on a list of domains have two levels of errors, one for
//!     the whole call and one in each entry of `answer.domains`;
//!   - 2.3.3: the common error codes (the table the classification below is built from) and the
//!     codes `ONLY_POST_ALLOWED` and `QUERY_PARAMS_DISALLOWED` ("pass parameters in form data");
//!   - 2.4.3: when the account has at least one SSL certificate loaded in its API settings, every
//!     request must present it, whatever the way of authentication;
//!   - 4.1: the function `nop` ("nothing, plus the login and ID of the authenticated user") at
//!     `{base}/nop`, with the answer `{"login", "user_id"}` and `PASSWORD_AUTH_FAILED` for wrong
//!     credentials;
//!   - 9.2 `zone/add_alias`: `subdomain` (`@` for the domain itself, `*` for every subdomain not
//!     named in other records) and `ipaddr`, the IPv4 address; 9.3 `zone/add_aaaa`: the same
//!     fields with an IPv6 address; neither has a TTL parameter;
//!   - 9.1 `zone/nop`: whether the zone of a domain can be managed; the answer is `domains`
//!     with `result` per domain; "managing the zone is possible only if the domain uses the name
//!     servers ns1.reg.ru and ns2.reg.ru";
//!   - 9.9 `zone/add_txt`: `subdomain`, `text` ("only alphanumeric characters of the ASCII
//!     set"), the errors `TEXT_NOT_FOUND`, `TEXT_TOOLONG`, `TEXT_CONTAINS_INVALID_CHARACTERS`;
//!     there is no TTL parameter;
//!   - 9.11 `zone/get_resource_records`: `domains[].rrs[]` with `subname` (`@` for the domain
//!     itself, `*` for all other subdomains, or the name of the subdomain), `rectype`, `content`
//!     ("IP address for A, IPv6 address for AAAA, and others"), `prio` and `state` ("A: active;
//!     obsolete, present only for compatibility"); the zone's `soa` is an object of its own, not
//!     a record;
//!   - 9.18 `zone/remove_record`: `subdomain` and `record_type` required, `priority` optional
//!     ("default 0; not applicable to the removal of an A record and similar records"), `content`
//!     optional, "when it is absent, all records that satisfy the other parameters are marked for
//!     deletion";
//!   - 9.19 `zone/clear` deletes every record of a zone and is never called.
//! - lego `providers/dns/regru/internal/client.go` and `types.go`: the request bodies of
//!   `add_txt` and `remove_record` (`domains: [{dname}]`, `subdomain`, `text` or `content`,
//!   `record_type: "TXT"`, `output_content_type: "plain"`; client.go lines 41 to 74 and types.go
//!   lines 57 to 77), the form fields `username`, `password`, `input_data` and
//!   `input_format=json` (client.go lines 84 to 88), and the check of both levels of errors
//!   (types.go lines 22 to 36).
//!
//! Endpoints used, all below the `base_url`, all `POST`:
//!
//! | Call                  | Path                         | Idempotent |
//! | --------------------- | ---------------------------- | ---------- |
//! | credentials           | `/nop`                       | yes        |
//! | zone check            | `/zone/nop`                  | yes        |
//! | read records          | `/zone/get_resource_records` | yes        |
//! | add an A record       | `/zone/add_alias`            | no         |
//! | add an AAAA record    | `/zone/add_aaaa`             | no         |
//! | add a TXT record      | `/zone/add_txt`              | no         |
//! | remove by content     | `/zone/remove_record`        | no         |
//!
//! HTTP status. The documentation shows every answer, errors included, as a JSON object and
//! states no status for any of them; lego treats any non-2xx status as an error and reads both
//! levels of the JSON envelope on a 2xx. The client does the same: the shared status mapping of
//! the transport applies (401, 403, 429, 5xx), another 4xx is `Error::Rejected`, and the
//! envelope is read on every 2xx answer.
//!
//! The listing is the whole zone in one answer, bounded by the transport's 4 MiB cap alone
//! (design section 5.4): a zone whose records do not fit fails with `Error::Protocol`, it is
//! never read in part.

use std::fmt;

use reqwest::Method;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::http::{Endpoint, Http, Request, Response};
use crate::name::DomainName;
use crate::redact::Detail;

/// The record type names as the API spells them.
// Source: the documentation, 9.11 (`rectype`: "A, AAAA, CNAME, MX, NS and others") and 9.18
// (`record_type` "A" in the request example); lego types.go (`record_type: "TXT"`).
pub(super) const TXT: &str = "TXT";
pub(super) const A: &str = "A";
pub(super) const AAAA: &str = "AAAA";

/// `output_content_type` of every call: the form lego sends, which makes the answer plain
/// `text/plain` JSON.
// Source: the documentation, 2.2.4.2 (`output_content_type`: "for text/plain it is enough to say
// plain"); lego types.go lines 57 to 72.
const OUTPUT_CONTENT_TYPE: &str = "plain";

/// The API functions the client calls.
#[derive(Clone, Copy, Debug)]
enum Function {
    /// `nop`.
    Nop,
    /// `zone/nop`.
    ZoneNop,
    /// `zone/get_resource_records`.
    GetResourceRecords,
    /// `zone/add_alias`.
    AddAlias,
    /// `zone/add_aaaa`.
    AddAaaa,
    /// `zone/add_txt`.
    AddTxt,
    /// `zone/remove_record`.
    RemoveRecord,
}

impl Function {
    /// The path below the base URL.
    fn path(self) -> &'static str {
        match self {
            Function::Nop => "/nop",
            Function::ZoneNop => "/zone/nop",
            Function::GetResourceRecords => "/zone/get_resource_records",
            Function::AddAlias => "/zone/add_alias",
            Function::AddAaaa => "/zone/add_aaaa",
            Function::AddTxt => "/zone/add_txt",
            Function::RemoveRecord => "/zone/remove_record",
        }
    }

    /// Reads are safe to repeat; the writes are sent once (design section 5.3).
    fn idempotent(self) -> bool {
        matches!(
            self,
            Function::Nop | Function::ZoneNop | Function::GetResourceRecords
        )
    }
}

/// One entry of `domains` in a request.
#[derive(Serialize)]
struct DomainRef<'a> {
    dname: &'a str,
}

/// The `input_data` of a zone call: the one domain and the parameters of the function.
// Source: the documentation, 9.1, 9.2, 9.3, 9.9, 9.11 and 9.18 (request examples); lego types.go
// lines 57 to 77.
#[derive(Serialize)]
struct Input<'a> {
    domains: [DomainRef<'a>; 1],
    #[serde(skip_serializing_if = "Option::is_none")]
    subdomain: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipaddr: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_type: Option<&'a str>,
    output_content_type: &'static str,
}

impl<'a> Input<'a> {
    fn new(zone: &'a DomainName) -> Input<'a> {
        Input {
            domains: [DomainRef {
                dname: zone.without_dot(),
            }],
            subdomain: None,
            ipaddr: None,
            text: None,
            content: None,
            record_type: None,
            output_content_type: OUTPUT_CONTENT_TYPE,
        }
    }
}

/// The envelope of every answer.
// Source: the documentation, 2.3.2.
#[derive(Deserialize)]
struct Envelope {
    result: String,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    error_text: Option<String>,
    #[serde(default)]
    answer: Option<AnswerBody>,
}

#[derive(Deserialize)]
struct AnswerBody {
    #[serde(default)]
    domains: Option<Vec<DomainEntry>>,
}

/// One domain's part of an answer.
// Source: the documentation, 2.3.2 (per-domain `result`, `error_code`, `error_text`) and 9.11
// (`rrs`).
#[derive(Deserialize)]
struct DomainEntry {
    #[serde(default)]
    dname: Option<String>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    error_text: Option<String>,
    #[serde(default)]
    rrs: Option<Vec<Rr>>,
}

/// One resource record of a zone as `zone/get_resource_records` returns it; other fields are
/// ignored.
// Source: the documentation, 9.11 (`subname`, `rectype`, `content`).
#[derive(Debug, Deserialize)]
pub(super) struct Rr {
    /// The owner name relative to the domain: `@` for the domain itself.
    #[serde(default)]
    pub(super) subname: Option<String>,
    /// The record type.
    #[serde(default)]
    pub(super) rectype: Option<String>,
    /// The content.
    #[serde(default)]
    pub(super) content: Option<String>,
}

/// What an error code of the documentation's table means for the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Auth,
    Forbidden,
    RateLimited,
    Transient,
    InvalidInput,
    NotFound,
    Rejected,
}

/// The class of an error code.
///
/// Source: the documentation, 2.3.3 ("Общие коды ошибок"), the tables of authorization errors,
/// identification errors, availability errors and other errors, and 9.9 for the `TEXT_*` codes.
/// Codes the table does not list are `Rejected`.
fn classify(code: &str) -> Class {
    match code {
        "NO_USERNAME"
        | "NO_AUTH"
        | "PASSWORD_AUTH_FAILED"
        | "USER_AUTHENTICATION_FAILED"
        | "MORE_THAN_ONE_ACCOUNT_WITH_THE_SAME_EMAIL" => Class::Auth,
        // The account or the IP address is blocked, or the domain is protected against API
        // operations: the credentials are right and the operation is refused.
        "ACCESS_DENIED" | "ACCESS_DENIED_FROM_IP" | "ACCOUNT_BLOCKED" | "DOMAIN_PROTECTION" => {
            Class::Forbidden
        }
        // Source: the documentation, 1.2.
        "IP_EXCEEDED_ALLOWED_CONNECTION_RATE" | "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE" => {
            Class::RateLimited
        }
        // "Reg.API is temporarily unavailable"; an internal error leaves the outcome of a
        // write unknown.
        "SERVICE_UNAVAILABLE" | "INTERNAL_ERROR" => Class::Transient,
        "TEXT_NOT_FOUND" | "TEXT_TOOLONG" | "TEXT_CONTAINS_INVALID_CHARACTERS" => {
            Class::InvalidInput
        }
        "DOMAIN_NOT_FOUND"
        | "SERVICE_NOT_FOUND"
        | "SERVICE_ID_NOT_FOUND"
        | "INVALID_DOMAIN_NAME_FORMAT" => Class::NotFound,
        _ => Class::Rejected,
    }
}

/// The client's handle on the API: the transport, the endpoint and the credentials that go into
/// every request body.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    username: String,
    password: SecretString,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`. `http` already knows every secret; the credentials are kept to be put
    /// into each request's form body.
    pub(super) fn new(http: Http, base: Endpoint, username: String, password: SecretString) -> Api {
        Api {
            http,
            base,
            username,
            password,
        }
    }

    /// `nop`: authenticates and does nothing else, so a success proves that the credentials, and
    /// the client certificate if the account requires one, are accepted now.
    pub(super) async fn nop(&self) -> Result<(), Error> {
        self.send(Function::Nop, None).await.map(drop)
    }

    /// `zone/nop`: whether the zone of `zone` can be managed. `Error::ZoneNotFound` when the
    /// domain is not found or not the user's; `Error::Rejected` with the provider's reason when
    /// its zone cannot be managed (for example, other name servers).
    pub(super) async fn zone_nop(&self, zone: &DomainName) -> Result<(), Error> {
        self.zone_call(Function::ZoneNop, zone, &Input::new(zone))
            .await
            .map(drop)
    }

    /// Every resource record of the zone, of every type, in one answer.
    pub(super) async fn records(&self, zone: &DomainName) -> Result<Vec<Rr>, Error> {
        let entry = self
            .zone_call(Function::GetResourceRecords, zone, &Input::new(zone))
            .await?;
        // A success without the list is an answer the client cannot read, never an empty zone.
        let rrs = entry
            .rrs
            .ok_or_else(|| protocol("the provider's answer lacks the records of the zone"))?;
        if rrs
            .iter()
            .any(|rr| rr.subname.is_none() || rr.rectype.is_none())
        {
            return Err(protocol(
                "a record in the provider's answer lacks its name or its type",
            ));
        }
        Ok(rrs)
    }

    /// Adds a TXT record with `text` at `sub` ("@" for the zone itself). Sent once: the
    /// documentation does not say what a repeated add does.
    pub(super) async fn add_txt(
        &self,
        zone: &DomainName,
        sub: &str,
        text: &str,
    ) -> Result<(), Error> {
        let mut input = Input::new(zone);
        input.subdomain = Some(sub);
        input.text = Some(text);
        self.zone_call(Function::AddTxt, zone, &input)
            .await
            .map(drop)
    }

    /// Adds an A record (`zone/add_alias`) or an AAAA record (`zone/add_aaaa`) with the address
    /// `ipaddr` at `sub` ("@" for the zone itself). Sent once: the documentation does not say what
    /// a repeated add does.
    pub(super) async fn add_address(
        &self,
        zone: &DomainName,
        sub: &str,
        record_type: &str,
        ipaddr: &str,
    ) -> Result<(), Error> {
        let function = match record_type {
            A => Function::AddAlias,
            AAAA => Function::AddAaaa,
            _ => {
                return Err(Error::InvalidInput {
                    detail: Detail::constant("the record type has no address function"),
                });
            }
        };
        let mut input = Input::new(zone);
        input.subdomain = Some(sub);
        input.ipaddr = Some(ipaddr);
        self.zone_call(function, zone, &input).await.map(drop)
    }

    /// Removes the records of type `record_type` at `sub` whose content is `content`. Sent once.
    /// No `priority` is sent: the client removes only types to which it does not apply
    /// (documentation 9.18).
    ///
    /// A `content` that is empty or only white space is refused before any request: with no
    /// content the function removes every record of the type at the name (documentation 9.18),
    /// which is never what this client means, and whether the API trims white space before it
    /// looks at the field is not documented. The layers above only ever pass the content of a
    /// record as the listing returned it; the check guards the request itself.
    pub(super) async fn remove_record(
        &self,
        zone: &DomainName,
        sub: &str,
        record_type: &str,
        content: &str,
    ) -> Result<(), Error> {
        if content.trim().is_empty() {
            return Err(Error::InvalidInput {
                detail: Detail::constant("a record is removed only by a non-empty content"),
            });
        }
        let mut input = Input::new(zone);
        input.subdomain = Some(sub);
        input.content = Some(content);
        input.record_type = Some(record_type);
        self.zone_call(Function::RemoveRecord, zone, &input)
            .await
            .map(drop)
    }

    /// A call that works on one domain: returns that domain's entry of the answer when its
    /// `result` is `success`, else the error of the code it names.
    async fn zone_call(
        &self,
        function: Function,
        zone: &DomainName,
        input: &Input<'_>,
    ) -> Result<DomainEntry, Error> {
        let (envelope, status) = self.send(function, Some(input)).await?;
        let domains = envelope
            .answer
            .and_then(|answer| answer.domains)
            .ok_or_else(|| protocol("the provider's answer lists no domains"))?;
        // Exactly the one domain asked for: an answer for another domain, or for none, is not
        // an answer to this call (a missing entry must never read as success).
        let Ok([entry]) = <[DomainEntry; 1]>::try_from(domains) else {
            return Err(protocol(
                "the provider's answer does not hold exactly the domain asked for",
            ));
        };
        match entry.result.as_deref() {
            Some("success") => {}
            Some(_) => {
                return Err(self.failure(
                    zone,
                    status,
                    entry.error_code.as_deref(),
                    entry.error_text.as_deref(),
                ));
            }
            None => {
                return Err(protocol(
                    "the provider's answer for the domain has no result",
                ));
            }
        }
        match entry.dname.as_deref().map(DomainName::parse) {
            Some(Ok(stated)) if stated == *zone => Ok(entry),
            _ => Err(protocol(
                "the provider answered about a domain other than the one asked for",
            )),
        }
    }

    /// One POST. Returns the envelope of a `success` and the HTTP status; a failure at the HTTP
    /// level or in the envelope is the error.
    async fn send(
        &self,
        function: Function,
        input: Option<&Input<'_>>,
    ) -> Result<(Envelope, u16), Error> {
        let url = self.base.url().path(function.path()).build()?;
        let data = match input {
            Some(input) => Some(
                serde_json::to_string(input).map_err(|_| Error::InvalidInput {
                    detail: Detail::constant("the request cannot be encoded"),
                })?,
            ),
            None => None,
        };
        // The credentials are form fields of their own, never inside `input_data` (2.2.4.2).
        let mut pairs = vec![
            ("username", self.username.as_str()),
            ("password", self.password.expose_secret()),
        ];
        if let Some(data) = &data {
            pairs.push(("input_format", "json"));
            pairs.push(("input_data", data.as_str()));
        }
        let mut request = Request::new(Method::POST, url).form(&pairs);
        if function.idempotent() {
            request = request.idempotent();
        }
        let response = self.http.send(&request).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let status = response.status();
        let Ok(envelope) = serde_json::from_slice::<Envelope>(response.body()) else {
            return Err(self.unreadable(&response));
        };
        match envelope.result.as_str() {
            "success" => Ok((envelope, status)),
            // Documentation 2.3.2 shows the error answer with `result: "error"` and, for some
            // simple commands, with the reason in `result`; the code decides.
            _ if envelope.error_code.is_some() => Err(self.failure_in(
                status,
                envelope.error_code.as_deref(),
                envelope.error_text.as_deref(),
                None,
            )),
            _ => Err(self.unreadable(&response)),
        }
    }

    /// The error of an error code of a domain's entry.
    fn failure(
        &self,
        zone: &DomainName,
        status: u16,
        code: Option<&str>,
        text: Option<&str>,
    ) -> Error {
        self.failure_in(status, code, text, Some(zone))
    }

    /// The error of an error code. `zone` names the domain the call was about, for `NotFound`.
    fn failure_in(
        &self,
        status: u16,
        code: Option<&str>,
        text: Option<&str>,
        zone: Option<&DomainName>,
    ) -> Error {
        let code = code.unwrap_or("UNKNOWN");
        let detail = || {
            self.http
                .detail(&format!("{code}: {}", text.unwrap_or_default()))
        };
        match classify(code) {
            Class::Auth => Error::Auth { detail: detail() },
            Class::Forbidden => Error::Forbidden { detail: detail() },
            Class::RateLimited => Error::RateLimited { retry_after: None },
            Class::Transient => Error::Transient { detail: detail() },
            Class::InvalidInput => Error::InvalidInput { detail: detail() },
            Class::NotFound => match zone {
                Some(zone) => Error::zone_not_found(zone.clone()),
                None => Error::Rejected {
                    status: Some(status),
                    detail: detail(),
                },
            },
            Class::Rejected => Error::Rejected {
                status: Some(status),
                detail: detail(),
            },
        }
    }

    /// An answer that is not the documented envelope, as a protocol error with the scrubbed
    /// start of the body.
    fn unreadable(&self, response: &Response) -> Error {
        Error::Protocol {
            detail: self.http.detail(&format!(
                "status {}: {}",
                response.status(),
                self.http.body_detail(response)
            )),
        }
    }

    /// An HTTP status the client does not expect. 401, 403, 429 and 5xx were mapped by the
    /// transport already; another 4xx is the provider refusing the request.
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400..=499 => self.http.reject(response),
            _ => self.unreadable(response),
        }
    }
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

/// The provider's error message: `error_code` and `error_text` of the documented error answer.
// Source: the documentation, 2.3.2.
pub(super) fn error_message(body: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct ErrorBody {
        #[serde(default)]
        error_code: Option<String>,
        #[serde(default)]
        error_text: Option<String>,
    }
    let body: ErrorBody = serde_json::from_str(body).ok()?;
    match (
        body.error_code.filter(|c| !c.is_empty()),
        body.error_text.filter(|t| !t.is_empty()),
    ) {
        (Some(code), Some(text)) => Some(format!("{code}: {text}")),
        (Some(code), None) => Some(code),
        (None, Some(text)) => Some(text),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::{Api, Class, classify, error_message};
    use crate::error::ErrorKind;
    use crate::http::testing;
    use crate::http::{Endpoint, Http};
    use crate::id::ProviderId;
    use crate::name::DomainName;

    /// With no `content` the API removes every record of the type at the name (documentation
    /// 9.18), so an empty content is refused before a request is made. Nothing listens at the
    /// address: a request would be `Transient`, not `InvalidInput`.
    #[tokio::test]
    async fn an_empty_content_is_never_sent() {
        let ctx = testing::context(testing::options());
        let base = Endpoint::parse("base_url", "http://127.0.0.1:9/api/regru2", &ctx).unwrap();
        let http = Http::builder(&ctx, ProviderId::Regru)
            .endpoint(&base)
            .build()
            .unwrap();
        let api = Api::new(
            http,
            base,
            "u".to_owned(),
            SecretString::from("p".to_owned()),
        );
        let zone = DomainName::parse("example.org").unwrap();
        for content in ["", " ", "\t", "\n", " \r\n "] {
            for rtype in [super::TXT, super::A, super::AAAA] {
                let e = api
                    .remove_record(&zone, "x", rtype, content)
                    .await
                    .unwrap_err();
                assert_eq!(e.kind(), ErrorKind::InvalidInput, "{content:?}: {e:?}");
            }
        }
    }

    #[test]
    fn error_messages_join_code_and_text() {
        for (body, expected) in [
            (
                r#"{"result":"error","error_code":"PASSWORD_AUTH_FAILED","error_text":"Username\/password Incorrect"}"#,
                Some("PASSWORD_AUTH_FAILED: Username/password Incorrect"),
            ),
            (r#"{"error_code":"X"}"#, Some("X")),
            (r#"{"error_text":"only this"}"#, Some("only this")),
            (r#"{"result":"success"}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn codes_of_the_documentation_are_classified() {
        for (code, class) in [
            ("PASSWORD_AUTH_FAILED", Class::Auth),
            ("NO_USERNAME", Class::Auth),
            ("ACCESS_DENIED_FROM_IP", Class::Forbidden),
            ("ACCOUNT_BLOCKED", Class::Forbidden),
            ("IP_EXCEEDED_ALLOWED_CONNECTION_RATE", Class::RateLimited),
            (
                "ACCOUNT_EXCEEDED_ALLOWED_CONNECTION_RATE",
                Class::RateLimited,
            ),
            ("SERVICE_UNAVAILABLE", Class::Transient),
            ("TEXT_TOOLONG", Class::InvalidInput),
            ("DOMAIN_NOT_FOUND", Class::NotFound),
            ("DOMAIN_IS_NOT_USE_REGRU_NSS", Class::Rejected),
            ("SOMETHING_NEW", Class::Rejected),
        ] {
            assert_eq!(classify(code), class, "{code}");
        }
    }
}
