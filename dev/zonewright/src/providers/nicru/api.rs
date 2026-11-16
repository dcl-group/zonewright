//! The nic.ru DNS hosting API as this client uses it: the token exchange, one function per
//! endpoint, the XML of requests and answers, and the classification of answers. Nothing here
//! knows the value or record layer, the zone lock or the staged-change marks; `client.rs`,
//! `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Docs]: "API of DNS hosting", the provider's request description
//!   (`API_DNS-hosting-en.pdf`, 2013, linked from the help page
//!   <https://www.nic.ru/help/api-of-dns-hosting_1579.html>). The provider's site refuses
//!   automated readers; the copy read is the Internet Archive's of 2024-09-13
//!   (<https://web.archive.org/web/20240913045907/https://www.nic.ru/help/upload/file/API_DNS-hosting-en.pdf>),
//!   checked against the Russian edition of 2022-05-15. Section numbers below are the
//!   document's.
//! - lego `providers/dns/nicru` (`nicru.go`, `internal/client.go`, `internal/identity.go`,
//!   `internal/types.go` and the fixtures under `internal/fixtures/`), at commit `dc719e6`.
//!
//! Endpoints used, all below the `base_url` unless stated:
//!
//! | Call          | Request                                              | Docs  |
//! | ------------- | ---------------------------------------------------- | ----- |
//! | token         | `POST {token_url}` (form)                            | 2.2   |
//! | list zones    | `GET /zones`                                         | 3.2.1 |
//! | list records  | `GET /services/{service}/zones/{zone}/records`       | 4.5.2 |
//! | add record    | `PUT /services/{service}/zones/{zone}/records` (XML) | 4.5.1 |
//! | delete record | `DELETE /services/{service}/zones/{zone}/records/{id}` | 4.5.3 |
//! | commit        | `POST /services/{service}/zones/{zone}/commit`       | 4.3.1 |
//! | rollback      | `POST /services/{service}/zones/{zone}/rollback`     | 4.2   |
//!
//! A record is `<rr>` with `name`, an optional `ttl`, `type` and one element per type (Docs 4.6,
//! the form of a request body; the listing of 4.5.2 shows the same form for SOA and NS, with an
//! `idn-name` next to every `name`). [`SHAPES`] holds the elements of the types the document
//! shows.
//!
//! Every answer of the DNS API is `<response><status>success</status>…</response>`, or
//! `<status>fail</status>` with `<errors><error code="…">text</error></errors>`. The
//! documentation says a failure comes "with the error code" and, for one call, with HTTP status
//! 200, so the client reads the `status` element whatever the HTTP status. The one error code
//! the documentation names is `4097`, "Access token expired or not found".

use std::fmt;

use bytes::Bytes;
use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;

use crate::error::{Error, ErrorKind};
use crate::http::encode::{self, xml_escape};
use crate::http::{Endpoint, Http, Request, Response, Token, TokenAuth, TokenSource};
use crate::name::DomainName;
use crate::redact::Detail;

/// The error code of a rejected token.
// Source: Docs, every error example ("<error code=\"4097\">Access token expired or not
// found</error>"); lego internal/fixtures/errors.xml.
const TOKEN_REJECTED: &str = "4097";

/// Media type of the DNS API's requests and answers.
// Source: lego internal/client.go:242-246 (`Accept: text/xml`, and `Content-Type: text/xml`
// with a body); Docs section 1 (XML in requests and responses).
const TEXT_XML: &str = "text/xml";

/// The TXT record type, whose element holds one or more `string` elements.
pub(super) const TXT: &str = "TXT";

/// Where the fields of one record type sit in its element.
#[derive(Debug)]
pub(super) struct Shape {
    /// The type as the API spells it in `type`.
    pub(super) rtype: &'static str,
    /// The type's element inside `rr`.
    element: &'static str,
    /// The path of each field below the element, in the order of the type's presentation
    /// format; an empty path is the element's own text.
    fields: &'static [&'static [&'static str]],
}

impl Shape {
    /// The number of fields.
    pub(super) fn len(&self) -> usize {
        self.fields.len()
    }
}

/// The record elements the documentation shows, other than TXT.
// Source: Docs 4.6.1 (SOA: `soa` with `mname/name`, `rname/name`, `serial`, `refresh`, `retry`,
// `expire`, `minimum`), 4.6.2 (A: `<a>IP</a>`), 4.6.3 (AAAA: `<aaaa>ipv6</aaaa>`), 4.6.4 (CNAME:
// `cname/name`), 4.6.5 (NS: `ns/name`), 4.6.6 (MX: `mx` with `preference` and `exchange/name`),
// 4.6.7 (SRV: `srv` with `priority`, `weight`, `port` and `target/name`), 4.6.8 (PTR: `ptr/name`),
// 4.6.10 (DNAME: `dname/name`), 4.6.11 (HINFO: `hinfo` with `hardware` and `os`), 4.6.12
// (NAPTR: `naptr` with `order`, `preference`, `flags`, `service`, `regexp` and
// `replacement/name`), 4.6.13 (RP: `rp` with `mbox-dname/name` and `txt-dname/name`). The
// listing examples of 4.5.1 and 4.5.2 show SOA and NS in the same form.
pub(super) const SHAPES: &[Shape] = &[
    Shape {
        rtype: "A",
        element: "a",
        fields: &[&[]],
    },
    Shape {
        rtype: "AAAA",
        element: "aaaa",
        fields: &[&[]],
    },
    Shape {
        rtype: "CNAME",
        element: "cname",
        fields: &[&["name"]],
    },
    Shape {
        rtype: "NS",
        element: "ns",
        fields: &[&["name"]],
    },
    Shape {
        rtype: "PTR",
        element: "ptr",
        fields: &[&["name"]],
    },
    Shape {
        rtype: "DNAME",
        element: "dname",
        fields: &[&["name"]],
    },
    Shape {
        rtype: "MX",
        element: "mx",
        fields: &[&["preference"], &["exchange", "name"]],
    },
    Shape {
        rtype: "SRV",
        element: "srv",
        fields: &[&["priority"], &["weight"], &["port"], &["target", "name"]],
    },
    Shape {
        rtype: "SOA",
        element: "soa",
        fields: &[
            &["mname", "name"],
            &["rname", "name"],
            &["serial"],
            &["refresh"],
            &["retry"],
            &["expire"],
            &["minimum"],
        ],
    },
    Shape {
        rtype: "HINFO",
        element: "hinfo",
        fields: &[&["hardware"], &["os"]],
    },
    Shape {
        rtype: "NAPTR",
        element: "naptr",
        fields: &[
            &["order"],
            &["preference"],
            &["flags"],
            &["service"],
            &["regexp"],
            &["replacement", "name"],
        ],
    },
    Shape {
        rtype: "RP",
        element: "rp",
        fields: &[&["mbox-dname", "name"], &["txt-dname", "name"]],
    },
];

/// The shape of `rtype` (any case), if the documentation shows one.
pub(super) fn shape(rtype: &str) -> Option<&'static Shape> {
    SHAPES
        .iter()
        .find(|shape| shape.rtype.eq_ignore_ascii_case(rtype))
}

/// The type-specific content of a record to stage.
#[derive(Clone, Copy, Debug)]
pub(super) enum Content<'a> {
    /// The fields of a type in [`SHAPES`], in its order.
    Fields(&'a Shape, &'a [String]),
    /// The character strings of a TXT record, each at most 255 bytes.
    Strings(&'a [String]),
}

/// A zone as `GET /zones` lists it.
// Source: Docs 3.2.1 and 3.2.2: `name` ("zone name in Punycode"), `service` ("service
// identifier"), `has-changes` ("zone has changes unloaded to DNS servers"), `has-primary`
// ("true – DNS-master service; false – Secondary service").
#[derive(Clone, Debug)]
pub(super) struct Zone {
    /// The zone name; `None` when it is not a valid name.
    pub(super) name: Option<DomainName>,
    /// The service the zone is placed under: the first path segment of its calls.
    pub(super) service: String,
    /// The zone has staged changes that are not committed.
    pub(super) has_changes: bool,
    /// The zone is placed under a DNS-master service. The record calls are described for
    /// DNS-master services only (Docs section 4); a Secondary service's zone is not usable.
    pub(super) primary: bool,
}

/// A resource record as `GET …/records` lists it.
// Source: Docs 4.5.2 and 4.6 (`rr` with the attribute `id`, the elements `name`, `idn-name`,
// `ttl`, `type` and one element per type; TXT is `<txt>(<string>text</string>)+</txt>`, "text
// — arbitrary binary data record, up to 255 bytes"); lego internal/types.go (`RR`, `TXT`).
#[derive(Clone, Debug)]
pub(super) struct Rr {
    /// The record's identifier.
    pub(super) id: String,
    /// The owner name; `None` when it is not a valid name.
    pub(super) owner: Option<DomainName>,
    /// The record type.
    pub(super) rtype: String,
    /// The TTL in seconds, if the record states one in numeric or BIND form.
    pub(super) ttl: Option<u32>,
    /// For TXT, the value: the strings joined; `None` when it cannot be read.
    pub(super) txt: Option<String>,
    /// For a type in [`SHAPES`], the text of each field in the shape's order; `None` for a
    /// field the record lacks. Empty for TXT and for a type the documentation does not show.
    pub(super) fields: Vec<Option<String>>,
}

/// The answer of `GET …/records`.
#[derive(Clone, Debug)]
pub(super) struct RecordListing {
    /// The `has-changes` attribute of the listed zone: whether it has staged changes. `None`
    /// when the answer does not state it.
    pub(super) has_changes: Option<bool>,
    /// Every record of the zone.
    pub(super) records: Vec<Rr>,
}

/// The JSON answer of the token endpoint; other fields are ignored.
// Source: lego internal/fixtures/auth.json (`token_type`, `expires_in`, `access_token`,
// `refresh_token`); RFC 6749 section 5.1 (`expires_in` is optional).
#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// What an answer of the DNS API says.
enum Answer {
    /// `status` is `success`; the body text.
    Success(String),
    /// Error `4097`: the token was not accepted.
    TokenRejected,
}

/// The failure of an edit (staging a record or the deletion of one).
#[derive(Debug)]
pub(super) struct EditError {
    /// The operation's error.
    pub(super) error: Error,
    /// The edit was certainly not applied: it was refused by the answer to its one request,
    /// or never sent. False whenever it may have been applied: no answer, a 5xx, an answer the
    /// client cannot read.
    pub(super) refused: bool,
}

impl EditError {
    fn new(error: Error, refused: bool) -> EditError {
        EditError { error, refused }
    }
}

/// The client's handle on the API: the transport, the endpoints and the token.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    token_url: Url,
    /// The form body of the token request, built once in a zeroizing buffer.
    grant: Bytes,
    tokens: TokenSource,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// The API at `base`, with tokens from `token` obtained with the form body `grant`
    /// (built by `grant()`).
    pub(super) fn new(http: Http, base: Endpoint, token: &Endpoint, grant: Bytes) -> Api {
        Api {
            http,
            base,
            token_url: token.as_url().clone(),
            grant,
            tokens: TokenSource::new(None),
        }
    }

    /// A [`Detail`] from text taken from an answer, scrubbed of every secret of the client.
    pub(super) fn detail(&self, text: &str) -> Detail {
        self.http.detail(text)
    }

    /// The password grant. A `400` or `401` is `Error::Auth`.
    // Source: Docs 2.2; RFC 6749 section 5.2 (a refused grant is `400` with `error`). The answer
    // is read as lego's fixture shows it; a token without `expires_in` is assumed to live an
    // hour (design section 5.7).
    async fn fetch(&self) -> Result<Token, Error> {
        let request = Request::new(Method::POST, self.token_url.clone())
            .idempotent()
            .anonymous()
            .body(encode::FORM, self.grant.clone())
            .keep_status(400);
        let response = self.http.send(&request).await?;
        if response.status() == 400 {
            return Err(Error::Auth {
                detail: self.http.body_detail(&response),
            });
        }
        if !response.is_success() {
            return Err(self.http.reject(&response));
        }
        let answer: TokenAnswer =
            response.json("the token endpoint's answer is not in the expected form")?;
        if answer.access_token.is_empty() {
            return Err(protocol("the token endpoint issued an empty token"));
        }
        let lifetime = answer.expires_in.map(std::time::Duration::from_secs);
        Ok(Token::new(
            SecretString::from(answer.access_token),
            lifetime,
        ))
    }

    /// Exchanges the credentials for a new token, even when a valid one is cached: proves that
    /// they are accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens.renew(|| self.fetch()).await?;
        Ok(())
    }

    /// Sends the request `build` makes with the token, and reads the answer. Error `4097`
    /// discards the token; an idempotent request is then repeated once with a new one, and a
    /// second `4097` is `Error::Auth`. A request that is not idempotent is not repeated: the
    /// result is `Error::Transient`, and the caller's repeat of the operation obtains a new
    /// token (design section 5.3). An HTTP `401` takes the transport's path for a rejected
    /// token.
    // Source: Docs (code 4097 in every error example; `Authorization: Bearer <token>`).
    async fn call(
        &self,
        build: impl Fn() -> Result<Request, Error>,
        idempotent: bool,
        empty_ok: bool,
    ) -> Result<String, Error> {
        self.call_edit(build, idempotent, empty_ok)
            .await
            .map_err(|e| e.error)
    }

    /// [`Api::call`], with the error saying whether the request was certainly not applied. That
    /// is known only for a request that is sent once (`idempotent` false): a repeated request
    /// may have been applied by an attempt whose answer was lost.
    async fn call_edit(
        &self,
        build: impl Fn() -> Result<Request, Error>,
        idempotent: bool,
        empty_ok: bool,
    ) -> Result<String, EditError> {
        let mut renewed = false;
        loop {
            let request = build().map_err(|e| EditError::new(e, true))?;
            let response = match self
                .http
                .send_with_token(&request, &self.tokens, &TokenAuth::BEARER, || self.fetch())
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    // A request sent once and answered with one of these was refused by that
                    // answer (design sections 5.3 and 5.4: 401 for a fresh token, 403, 429, a
                    // 3xx) or never sent (a request that could not be built). The transport's
                    // `Transient` covers both a 5xx and a rejected cached token, so it counts
                    // as an unknown outcome.
                    let refused = !idempotent
                        && matches!(
                            e.kind(),
                            ErrorKind::Auth
                                | ErrorKind::Forbidden
                                | ErrorKind::RateLimited
                                | ErrorKind::Rejected
                                | ErrorKind::InvalidInput
                        );
                    return Err(EditError::new(e, refused));
                }
            };
            match self.answer(&response, empty_ok) {
                Ok(Answer::Success(text)) => return Ok(text),
                Ok(Answer::TokenRejected) => {
                    // Discards exactly the token this request carried; one that another call
                    // has fetched meanwhile is kept.
                    self.tokens.discard_rejected(&response).await;
                    if renewed {
                        let error = Error::Auth {
                            detail: Detail::constant(
                                "the provider rejected a newly issued token (error 4097)",
                            ),
                        };
                        return Err(EditError::new(error, !idempotent));
                    }
                    if !idempotent {
                        let error = Error::Transient {
                            detail: Detail::constant(
                                "the provider rejected the cached token (error 4097); repeating \
                                 the operation obtains a new one",
                            ),
                        };
                        return Err(EditError::new(error, true));
                    }
                    renewed = true;
                }
                Err(e) => {
                    // A `fail` answer, or another refusal, is certain; an answer the client
                    // cannot read says nothing about the outcome.
                    let refused = !idempotent && e.kind() != ErrorKind::Protocol;
                    return Err(EditError::new(e, refused));
                }
            }
        }
    }

    /// Reads an answer the transport passed on (2xx, and 4xx other than 401, 403 and 429): the
    /// `status` element decides. A body without one is the transport's default refusal for a
    /// non-2xx status and `Error::Protocol` for a 2xx one, except that `empty_ok` accepts an
    /// empty 2xx body (the documentation shows no body for a successful delete).
    fn answer(&self, response: &Response, empty_ok: bool) -> Result<Answer, Error> {
        let text = response.text();
        let success = response.is_success();
        if success && empty_ok && text.trim().is_empty() {
            return Ok(Answer::Success(String::new()));
        }
        let parsed = roxmltree::Document::parse(&text).ok();
        let status = parsed
            .as_ref()
            .and_then(|doc| child(doc.root_element(), "status"))
            .map(|node| node.text().unwrap_or("").trim().to_owned());
        let Some(status) = status else {
            if success {
                return Err(protocol(
                    "the provider's answer is not a response document with a status",
                ));
            }
            return Err(self.http.reject(response));
        };
        if status == "success" {
            if !success {
                return Err(protocol(
                    "the provider answered status success with an HTTP error status",
                ));
            }
            return Ok(Answer::Success(text.into_owned()));
        }
        let (code, message) = parsed
            .as_ref()
            .and_then(|doc| first_error(doc))
            .unwrap_or_default();
        if code == TOKEN_REJECTED {
            return Ok(Answer::TokenRejected);
        }
        let detail = if message.is_empty() && code.is_empty() {
            Detail::constant("the provider answered with status fail and no error")
        } else {
            self.http.detail(&format!("{message} (code {code})"))
        };
        // The `code` attribute of the first `error` element is the documented error code
        // (module documentation).
        Err(Error::Rejected {
            status: (!success).then_some(response.status()),
            detail,
            code: self.http.scrubber().code(&code),
        })
    }

    /// Every zone of every DNS hosting service of the contract. A zone without a name or a
    /// service is an unexpected answer, not a shorter list.
    // Source: Docs 3.2.1 ("GET https://api.nic.ru/dns-master/zones"); lego
    // internal/client.go:72-90 (`ListZones`).
    pub(super) async fn zones(&self) -> Result<Vec<Zone>, Error> {
        let url = self.base.url().path("/zones").build()?;
        let text = self
            .call(
                || Ok(Request::get(url.clone()).accept(TEXT_XML)),
                true,
                false,
            )
            .await?;
        let doc = parse(&text)?;
        let data = child(doc.root_element(), "data")
            .ok_or_else(|| protocol("the zone listing has no data element"))?;
        children(data, "zone")
            .map(|node| {
                let (Some(name), Some(service)) =
                    (node.attribute("name"), node.attribute("service"))
                else {
                    return Err(protocol("a listed zone has no name or no service"));
                };
                // Whether the zone has staged changes decides between refusing, committing
                // and going on, so anything but the two documented values is unexpected.
                let has_changes = match node.attribute("has-changes") {
                    Some("true") => true,
                    Some("false") => false,
                    _ => {
                        return Err(protocol(
                            "a listed zone does not say whether it has staged changes",
                        ));
                    }
                };
                Ok(Zone {
                    name: DomainName::parse(name.trim()).ok(),
                    service: service.trim().to_owned(),
                    has_changes,
                    // Assumption (not documented): a zone without the attribute is treated as
                    // one of a DNS-master service; its record calls would then fail.
                    primary: node.attribute("has-primary") != Some("false"),
                })
            })
            .collect()
    }

    /// The URL of a call below one zone: `/services/{service}/zones/{zone}` and `tail`. The
    /// service identifier comes from the provider and goes through the identifier check; the
    /// zone is the caller's name in Punycode without the trailing dot.
    // Source: Docs 4.3.1, 4.5.1-4.5.3 (`<service>` "service identifier", `<zone_name>` "domain
    // zone in Punycode"); lego internal/client.go:113,138,154,170 (`JoinPath`).
    fn zone_url(
        &self,
        service: &str,
        zone: &DomainName,
        tail: &'static str,
    ) -> crate::http::url::UrlBuilder {
        self.base
            .url()
            .path("/services")
            .id(service)
            .path("/zones")
            .segment(zone.without_dot())
            .path(tail)
    }

    /// Every record of the zone, and whether the answer says the zone has staged changes. The
    /// answer holds the whole zone in one document, bounded by the transport's 4 MiB limit
    /// (design section 5.4). An answer without the zone element, with a record without an
    /// identifier, a name or a type, or with a `has-changes` other than `true` or `false`, is an
    /// unexpected answer.
    // Source: Docs 4.5.2 (the listed `zone` carries `has-changes`); lego
    // internal/client.go:112-135 (`GetRecords` joins the `rr` of every `zone` of `data`).
    pub(super) async fn records(
        &self,
        service: &str,
        zone: &DomainName,
    ) -> Result<RecordListing, Error> {
        let url = self.zone_url(service, zone, "/records").build()?;
        let text = self
            .call(
                || Ok(Request::get(url.clone()).accept(TEXT_XML)),
                true,
                false,
            )
            .await?;
        let doc = parse(&text)?;
        let data = child(doc.root_element(), "data")
            .ok_or_else(|| protocol("the record listing has no data element"))?;
        let zones: Vec<_> = children(data, "zone").collect();
        if zones.is_empty() {
            return Err(protocol("the record listing has no zone element"));
        }
        let mut has_changes = None;
        for node in &zones {
            match node.attribute("has-changes") {
                None => {}
                Some("true") => has_changes = Some(true),
                Some("false") => has_changes = has_changes.or(Some(false)),
                Some(_) => {
                    return Err(protocol(
                        "the record listing does not say clearly whether the zone has staged \
                         changes",
                    ));
                }
            }
        }
        let mut records = Vec::new();
        for node in zones.iter().flat_map(|z| children(*z, "rr")) {
            let (Some(id), Some(name), Some(rtype)) = (
                node.attribute("id"),
                child_text(node, "name"),
                child_text(node, "type"),
            ) else {
                return Err(protocol(
                    "a listed record has no identifier, no name or no type",
                ));
            };
            let txt = if rtype.eq_ignore_ascii_case(TXT) {
                child(node, "txt").and_then(txt_value)
            } else {
                None
            };
            let fields = shape(&rtype).map_or_else(Vec::new, |shape| read_fields(node, shape));
            // `ttl` is optional (Docs 4.6): a record without one has the zone's default. One
            // that is present but does not parse is not read as "no TTL".
            let ttl = match child_text(node, "ttl") {
                None => None,
                Some(text) => Some(
                    parse_ttl(&text)
                        .ok_or_else(|| protocol("a listed record has a TTL that does not parse"))?,
                ),
            };
            records.push(Rr {
                id: id.trim().to_owned(),
                owner: owner(&name, zone),
                rtype,
                ttl,
                txt,
                fields,
            });
        }
        Ok(RecordListing {
            has_changes,
            records,
        })
    }

    /// Stages one TXT record. `ttl` `None` sends none, so the zone's default applies. Sent once.
    // Source: Docs 4.5.1 (`PUT …/records`, `<request><rr-list>(<rr>…</rr>)+</rr-list></request>`)
    // and 4.6 (`ttl` is optional; "If ttl setting has not been set in the request, TTL default
    // value will be applied"), 4.6.9 (the TXT record); lego nicru.go:144-151 and
    // internal/fixtures/records_PUT_real-request.xml (the relative name `_acme-challenge`).
    pub(super) async fn add_txt(
        &self,
        service: &str,
        zone: &DomainName,
        owner: &str,
        value: &str,
        ttl: Option<u32>,
    ) -> Result<(), EditError> {
        let strings = [value.to_owned()];
        self.add_record(service, zone, owner, ttl, TXT, Content::Strings(&strings))
            .await
    }

    /// Stages one record of type `rtype` with `content`. `ttl` `None` sends none, so the zone's
    /// default applies. Sent once.
    // Source: Docs 4.5.1 and 4.6 (the request body, `ttl` optional), 4.6.2 to 4.6.9 (the type's
    // element).
    pub(super) async fn add_record(
        &self,
        service: &str,
        zone: &DomainName,
        owner: &str,
        ttl: Option<u32>,
        rtype: &str,
        content: Content<'_>,
    ) -> Result<(), EditError> {
        let url = self
            .zone_url(service, zone, "/records")
            .build()
            .map_err(|e| EditError::new(e, true))?;
        let body = Bytes::from(add_request(owner, ttl, rtype, content));
        self.call_edit(
            || {
                Ok(Request::new(Method::PUT, url.clone())
                    .accept(TEXT_XML)
                    .body(TEXT_XML, body.clone()))
            },
            false,
            false,
        )
        .await?;
        Ok(())
    }

    /// Stages the deletion of one record by its identifier. Sent once, although a deletion by
    /// identifier is idempotent (design section 5.3 allows a repeat, it does not require one):
    /// the API documents no answer for a record that is already deleted, so a repeat after a
    /// lost answer could not tell "deleted by the first attempt" from a refusal. A failed
    /// deletion whose outcome is unknown is settled by the caller from the zone's staged
    /// changes instead.
    // Source: Docs 4.5.3 ("If the request is successful, HTTP code 200 will be returned in the
    // response", no body shown); lego internal/client.go:137-151 and
    // internal/fixtures/record_DELETE.xml (a `success` answer).
    pub(super) async fn delete_record(
        &self,
        service: &str,
        zone: &DomainName,
        id: &str,
    ) -> Result<(), EditError> {
        let url = self
            .zone_url(service, zone, "/records")
            .id(id)
            .build()
            .map_err(|e| EditError::new(e, true))?;
        self.call_edit(
            || Ok(Request::new(Method::DELETE, url.clone()).accept(TEXT_XML)),
            false,
            true,
        )
        .await?;
        Ok(())
    }

    /// Commits the zone: publishes every staged change of it. Sent once; the caller decides
    /// about further attempts.
    // Source: Docs 4.3.1 ("Fixing zone version and zone upload to DNS servers", `POST
    // …/commit`, no body); lego internal/client.go:153-167.
    pub(super) async fn commit(&self, service: &str, zone: &DomainName) -> Result<(), Error> {
        let url = self.zone_url(service, zone, "/commit").build()?;
        self.call(
            || Ok(Request::new(Method::POST, url.clone()).accept(TEXT_XML)),
            false,
            false,
        )
        .await?;
        Ok(())
    }

    /// Rolls the zone back: discards every staged change of it. Sent once; the caller decides
    /// about further attempts.
    // Source: Docs 4.2 ("Cancellation of introduced changes in zone", `POST …/rollback`, no body,
    // a `success` answer).
    pub(super) async fn rollback(&self, service: &str, zone: &DomainName) -> Result<(), Error> {
        let url = self.zone_url(service, zone, "/rollback").build()?;
        self.call(
            || Ok(Request::new(Method::POST, url.clone()).accept(TEXT_XML)),
            false,
            false,
        )
        .await?;
        Ok(())
    }
}

/// The form body of the token request, in a zeroizing buffer: the user name, the password, the
/// application's ID and secret, and the scope.
// Source: Docs 2.2 (`grant_type=password`, `username`, `password`, `scope`, form-encoded). The
// documentation sends the application's ID and secret in a Basic header; this client sends them
// as `client_id` and `client_secret` in the body, as lego does (internal/identity.go:20,
// `oauth2.AuthStyleInParams`), which RFC 6749 section 2.3.1 allows.
pub(super) fn grant(
    username: &str,
    scope: &str,
    password: &SecretString,
    client_id: &SecretString,
    client_secret: &SecretString,
) -> Bytes {
    encode::wiped_text(encode::form(&[
        ("grant_type", "password"),
        ("username", username),
        ("password", password.expose_secret()),
        ("client_id", client_id.expose_secret()),
        ("client_secret", client_secret.expose_secret()),
        ("scope", scope),
    ]))
}

/// The body of `PUT …/records` with one record. Every value goes through the one XML escaping
/// function; element names are constants.
// Source: Docs 4.5.1, 4.6 and the type's section of 4.6; lego internal/types.go (`Request`,
// `RRList`, `RR` with `name`, `ttl`, `type`, `txt` / `string`, in that order) and
// internal/client.go:220-235 (`xml.Header`).
pub(super) fn add_request(
    owner: &str,
    ttl: Option<u32>,
    rtype: &str,
    content: Content<'_>,
) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<request><rr-list><rr>");
    element(&mut xml, "name", owner);
    if let Some(ttl) = ttl {
        element(&mut xml, "ttl", &ttl.to_string());
    }
    match content {
        Content::Strings(strings) => {
            element(&mut xml, "type", TXT);
            xml.push_str("<txt>");
            for string in strings {
                element(&mut xml, "string", string);
            }
            xml.push_str("</txt>");
        }
        Content::Fields(shape, values) => {
            element(&mut xml, "type", rtype);
            open(&mut xml, shape.element);
            for (path, value) in shape.fields.iter().zip(values) {
                for tag in *path {
                    open(&mut xml, tag);
                }
                xml.push_str(&xml_escape(value));
                for tag in path.iter().rev() {
                    close(&mut xml, tag);
                }
            }
            close(&mut xml, shape.element);
        }
    }
    xml.push_str("</rr></rr-list></request>");
    xml
}

fn open(out: &mut String, tag: &str) {
    out.push('<');
    out.push_str(tag);
    out.push('>');
}

fn close(out: &mut String, tag: &str) {
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

/// The fields of `shape` in record `node`: the trimmed text at each path below the type's
/// element; `None` where an element is missing.
fn read_fields(node: roxmltree::Node<'_, '_>, shape: &Shape) -> Vec<Option<String>> {
    let element = child(node, shape.element);
    shape
        .fields
        .iter()
        .map(|path| {
            let mut at = element?;
            for tag in *path {
                at = child(at, tag)?;
            }
            Some(at.text().unwrap_or("").trim().to_owned())
        })
        .collect()
}

/// A TTL in numeric form or in the BIND form of numbers with the units `w`, `d`, `h`, `m` and
/// `s` (`1h30m`); `None` for anything else or a value beyond `u32`.
// Source: Docs 4.6 ("ttl setting … may be set both in numeric form and in wdhs form maintained
// by BIND").
pub(super) fn parse_ttl(text: &str) -> Option<u32> {
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse().ok();
    }
    let mut total: u32 = 0;
    let mut number: Option<u32> = None;
    for c in text.chars() {
        if let Some(digit) = c.to_digit(10) {
            number = Some(number.unwrap_or(0).checked_mul(10)?.checked_add(digit)?);
            continue;
        }
        let unit: u32 = match c.to_ascii_lowercase() {
            'w' => 604_800,
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        total = total.checked_add(number.take()?.checked_mul(unit)?)?;
    }
    if number.is_some() || text.is_empty() {
        return None;
    }
    Some(total)
}

/// Appends `<tag>text</tag>` with `text` escaped.
fn element(out: &mut String, tag: &'static str, text: &str) {
    out.push('<');
    out.push_str(tag);
    out.push('>');
    out.push_str(&xml_escape(text));
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

/// The owner name of a record: relative to the zone (`@` for the apex), or absolute with a
/// trailing dot.
// Source: Docs 4.5.2 and lego internal/fixtures/records_GET*.xml (relative names, `@`); Docs
// 4.6.9 (the example writes `mail.test.ru.`, absolute); Docs 4.6 ("name setting may have value
// both in Punycode and in IDN").
fn owner(name: &str, zone: &DomainName) -> Option<DomainName> {
    DomainName::from_relative(name, zone).ok()
}

/// The value of a `txt` element: its `string` elements joined (design section 4.4). `None`
/// when it has none.
// Source: Docs 4.6.9 (`(<string>text</string>)+`). Assumption (not documented): lego trims the
// whitespace around every text node (internal/client.go:20-32, `Trimmer`), which suggests the
// answers may be indented. Whitespace around a string is removed only when it contains a line
// break, that is, when it is indentation; other surrounding spaces are kept, so a foreign value
// that differs from ours by a space never compares equal to it.
fn txt_value(txt: roxmltree::Node<'_, '_>) -> Option<String> {
    let strings: Vec<String> = children(txt, "string")
        .map(|s| strip_indentation(s.text().unwrap_or("")).to_owned())
        .collect();
    (!strings.is_empty()).then(|| strings.concat())
}

/// `text` without leading or trailing whitespace that contains a line break.
fn strip_indentation(text: &str) -> &str {
    let mut out = text;
    let start = out.len() - out.trim_start().len();
    if out.get(..start).is_some_and(|ws| ws.contains('\n')) {
        out = out.get(start..).unwrap_or(out);
    }
    let end = out.trim_end().len();
    if out.get(end..).is_some_and(|ws| ws.contains('\n')) {
        out = out.get(..end).unwrap_or(out);
    }
    out
}

/// The code and text of the first `error` element.
fn first_error(doc: &roxmltree::Document<'_>) -> Option<(String, String)> {
    let error = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "error")?;
    Some((
        error.attribute("code").unwrap_or("").trim().to_owned(),
        error.text().unwrap_or("").trim().to_owned(),
    ))
}

/// The provider's error message for the transport's own error texts (401, 403, 5xx): the text
/// and code of the first `error` element. `None` when the body is not such a document.
pub(super) fn error_message(body: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let (code, text) = first_error(&doc)?;
    Some(format!("{text} (code {code})"))
}

fn parse(text: &str) -> Result<roxmltree::Document<'_>, Error> {
    roxmltree::Document::parse(text).map_err(|_| protocol("the provider's answer is not XML"))
}

fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, tag: &str) -> Option<roxmltree::Node<'a, 'i>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == tag)
}

fn children<'a, 'i>(
    node: roxmltree::Node<'a, 'i>,
    tag: &'static str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == tag)
}

fn child_text(node: roxmltree::Node<'_, '_>, tag: &str) -> Option<String> {
    child(node, tag).map(|c| c.text().unwrap_or("").trim().to_owned())
}

fn protocol(text: &'static str) -> Error {
    Error::Protocol {
        detail: Detail::constant(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_requests_escape_every_value() {
        let strings = ["a<b&c\"d".to_owned()];
        let xml = add_request("_acme-challenge", Some(30), TXT, Content::Strings(&strings));
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let rr = doc.descendants().find(|n| n.has_tag_name("rr")).unwrap();
        assert_eq!(child_text(rr, "name").unwrap(), "_acme-challenge");
        assert_eq!(child_text(rr, "ttl").unwrap(), "30");
        assert_eq!(child_text(rr, "type").unwrap(), "TXT");
        let txt = child(rr, "txt").unwrap();
        assert_eq!(txt_value(txt).unwrap(), "a<b&c\"d");
        let strings = ["v".to_owned()];
        assert!(!add_request("x", None, TXT, Content::Strings(&strings)).contains("<ttl>"));
    }

    #[test]
    fn add_requests_nest_the_documented_elements() {
        let mx = shape("mx").unwrap();
        let values = ["10".to_owned(), "mail.example.org.".to_owned()];
        let xml = add_request("@", None, "MX", Content::Fields(mx, &values));
        assert!(
            xml.contains(
                "<rr><name>@</name><type>MX</type><mx><preference>10</preference><exchange>\
                 <name>mail.example.org.</name></exchange></mx></rr>"
            ),
            "{xml}"
        );
        let a = shape("A").unwrap();
        let values = ["192.0.2.1".to_owned()];
        let xml = add_request("www", Some(60), "A", Content::Fields(a, &values));
        assert!(
            xml.contains("<name>www</name><ttl>60</ttl><type>A</type><a>192.0.2.1</a>"),
            "{xml}"
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let rr = doc.descendants().find(|n| n.has_tag_name("rr")).unwrap();
        assert_eq!(read_fields(rr, a), [Some("192.0.2.1".to_owned())]);
        let srv = shape("SRV").unwrap();
        assert_eq!(read_fields(rr, srv), [None, None, None, None]);
    }

    #[test]
    fn ttls_are_numeric_or_bind_units() {
        assert_eq!(parse_ttl("3600"), Some(3600));
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("1W2d"), Some(777_600));
        assert_eq!(parse_ttl("30s"), Some(30));
        for bad in ["", "1h30", "h", "-1", "1.5h", "99999999999", "1x"] {
            assert_eq!(parse_ttl(bad), None, "{bad}");
        }
    }

    #[test]
    fn indentation_is_stripped_and_spaces_are_kept() {
        assert_eq!(strip_indentation("\n      v1\n    "), "v1");
        assert_eq!(strip_indentation(" v1 "), " v1 ");
        assert_eq!(strip_indentation("v1"), "v1");
        assert_eq!(strip_indentation(""), "");
    }

    #[test]
    fn owners_are_relative_or_absolute() {
        let zone = DomainName::parse("example.org").unwrap();
        assert_eq!(owner("@", &zone).unwrap(), zone);
        assert_eq!(
            owner("_acme-challenge", &zone).unwrap().as_str(),
            "_acme-challenge.example.org."
        );
        assert_eq!(
            owner("Mail.Example.Org.", &zone).unwrap().as_str(),
            "mail.example.org."
        );
        assert!(owner("bad name", &zone).is_none());
    }

    #[test]
    fn error_messages_read_the_first_error() {
        let body = "<response><status>fail</status><errors><error code=\"4097\">Access token \
                    expired or not found</error></errors></response>";
        assert_eq!(
            error_message(body).unwrap(),
            "Access token expired or not found (code 4097)"
        );
        assert_eq!(error_message("{\"error\":\"x\"}"), None);
    }
}
