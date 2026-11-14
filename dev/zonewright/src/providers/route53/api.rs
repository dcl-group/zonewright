//! The Route 53 API as this client uses it: request signing, one function per endpoint, the XML
//! of requests and answers, and the classification of answers. Nothing here knows the value
//! layer or the zone cache; `client.rs` and `txt.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [API reference]: `ListHostedZonesByName`, `GetHostedZone`, `ListResourceRecordSets`,
//!   `ChangeResourceRecordSets`, `GetChange`, `ResourceRecord`, [Common errors].
//! - [Quotas]: the limits of a change batch, the 400 `Throttling` and `PriorRequestNotComplete`
//!   answers.
//! - [Endpoints]: the endpoint and the signing Region.
//! - [SigV4] and its [troubleshooting] page: the signature (`crate::crypto::sigv4`) and the
//!   texts of signature errors.
//! - lego `providers/dns/route53/route53.go` at commit
//!   `c40c0a2a458a2dc77daaced6cb94a86e253dc8c1` (the file read on 2026-11-14).
//!
//! Endpoints used, all below the `base_url`:
//!
//! | Call            | Request                                                   | Success |
//! | --------------- | --------------------------------------------------------- | ------- |
//! | find zones      | `GET /2013-04-01/hostedzonesbyname?dnsname&hostedzoneid&maxitems` | 200 |
//! | get zone        | `GET /2013-04-01/hostedzone/{id}`                         | 200     |
//! | read rrset      | `GET /2013-04-01/hostedzone/{id}/rrset?maxitems&name&type` | 200    |
//! | change batch    | `POST /2013-04-01/hostedzone/{id}/rrset/`                 | 200     |
//! | change status   | `GET /2013-04-01/change/{id}`                             | 200     |
//!
//! [API reference]: https://docs.aws.amazon.com/Route53/latest/APIReference/
//! [Common errors]: https://docs.aws.amazon.com/Route53/latest/APIReference/CommonErrors.html
//! [Quotas]: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html
//! [Endpoints]: https://docs.aws.amazon.com/general/latest/gr/r53.html
//! [SigV4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
//! [troubleshooting]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-troubleshooting.html

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue};
use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use zeroize::Zeroizing;

use crate::crypto::sigv4;
use crate::error::Error;
use crate::http::encode::{self, xml_escape};
use crate::http::pager::MAX_PAGES;
use crate::http::request::sensitive_value;
use crate::http::url::UrlBuilder;
use crate::http::{
    Attempt, Endpoint, Finish, Http, Outgoing, PollStep, Poller, Request, Response, path_id,
};
use crate::name::DomainName;
use crate::redact::Detail;

use super::config::zone_id;

/// The XML namespace of requests.
// Source: API reference, `ChangeResourceRecordSets` request syntax
// (`xmlns="https://route53.amazonaws.com/doc/2013-04-01/"`).
const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";

/// Route 53 is signed in `us-east-1` with the service name `route53` (design section 11.3).
// Source: Endpoints page ("When you use the Route 53 API to submit requests, use the same
// Regions as above to sign requests": us-east-1 outside the China Regions).
const SCOPE: sigv4::Scope<'static> = sigv4::Scope {
    region: "us-east-1",
    service: "route53",
};

/// The signed request date header.
// Source: SigV4 documentation ("host and x-amz-date are required headers for all signed
// requests").
const X_AMZ_DATE: HeaderName = HeaderName::from_static("x-amz-date");

/// The session token header of temporary security credentials.
// Source: SigV4 documentation, "Add the signature to the request": with temporary credentials
// the session token goes in `X-Amz-Security-Token`, which is signed.
const X_AMZ_SECURITY_TOKEN: HeaderName = HeaderName::from_static("x-amz-security-token");

/// Elements that make an rrset something other than plain records: an alias, or a routing
/// policy other than simple (design section 3.4).
// Source: API reference, `ResourceRecordSet`: `AliasTarget` ("Alias resource record sets
// only"), `SetIdentifier` ("Resource record sets that have a routing policy other than
// simple"), `Weight`, `Region`, `Failover`, `GeoLocation`, `GeoProximityLocation`,
// `MultiValueAnswer`, `CidrRoutingConfig` (the routing policies), `HealthCheckId` ("useful
// only when Route 53 is choosing between two or more resource record sets"),
// `TrafficPolicyInstanceId` (sets a traffic policy instance created).
const NOT_PLAIN: [&str; 11] = [
    "AliasTarget",
    "SetIdentifier",
    "Weight",
    "Region",
    "Failover",
    "GeoLocation",
    "GeoProximityLocation",
    "MultiValueAnswer",
    "CidrRoutingConfig",
    "HealthCheckId",
    "TrafficPolicyInstanceId",
];

/// Page size of an rrset listing.
// Source: API reference, `ListResourceRecordSets`: "returns up to 300 resource record sets at a
// time".
const RRSET_PAGE: &str = "300";

/// Page size of a hosted zone listing.
// Source: API reference, `ListHostedZonesByName`: "Route 53 returns up to 100 items in each
// response".
const ZONE_PAGE: &str = "100";

/// Most polls of a change (design section 3.7).
const MAX_POLLS: u32 = 60;

/// Error codes that mean the signature or the credentials were refused.
// Source: Common errors (`IncompleteSignature`, `ExpiredTokenException`,
// `UnrecognizedClientException`, all 403); SigV4 troubleshooting (`SignatureDoesNotMatch`, 403;
// "Missing Authentication Token"). Assumption (not documented for Route 53):
// `InvalidClientTokenId`, `ExpiredToken` and `MissingAuthenticationToken` are the codes of the
// same refusals; a wrong guess only turns `Auth` into `Forbidden`.
const AUTH_CODES: [&str; 8] = [
    "SignatureDoesNotMatch",
    "IncompleteSignature",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
    "MissingAuthenticationToken",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidSignatureException",
];

/// Error codes of a refused request rate. An HTTP 400 answer with one of them is a rate-limit
/// answer, which the transport treats like a 429 ([`throttled`]).
// Source: Quotas (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html,
// "HTTP 400 ... a Code element with a value of Throttling" and "PriorRequestNotComplete");
// API reference, `ChangeResourceRecordSets`, errors (`PriorRequestNotComplete`, HTTP 400);
// Common errors (https://docs.aws.amazon.com/Route53/latest/APIReference/CommonErrors.html,
// `ThrottlingException`, 400).
const RATE_CODES: [&str; 3] = [
    "Throttling",
    "ThrottlingException",
    "PriorRequestNotComplete",
];

/// Message prefixes of a signature refused for its date.
// Source: SigV4 troubleshooting, "Credential scope errors" ("Signature expired: ... is now
// earlier than ...", "Signature not yet current: ... is still later than ..."). Assumption
// (not documented for Route 53): the codes `RequestExpired` and `RequestTimeTooSkewed` mean the
// same.
const CLOCK_MESSAGES: [&str; 2] = ["Signature expired", "Signature not yet current"];
const CLOCK_CODES: [&str; 2] = ["RequestExpired", "RequestTimeTooSkewed"];

/// The hint added to a signature refused for its date (design section 11.3).
const CLOCK_HINT: &str = "the signature date was refused: the local clock differs from AWS time by more than 5 minutes; check the clock synchronization";

/// Markers after which an error message repeats the canonical request or the string to sign,
/// which carry the session token (design section 5.5).
// Source: SigV4 troubleshooting ("Compare the canonical request and string to your signed
// request with the value in the error message").
const CANONICAL_MARKERS: [&str; 3] = ["\n\n", "The Canonical String", "The String-to-Sign"];

/// A hosted zone as the listing and `GetHostedZone` return it.
// Source: API reference, `HostedZone` (`Id`, `Name`, `Config.PrivateZone`).
#[derive(Clone, Debug)]
pub(super) struct HostedZone {
    /// The ID, without the `/hostedzone/` prefix.
    pub(super) id: String,
    /// The name, if it is a valid domain name.
    pub(super) name: Option<DomainName>,
    /// A private zone is served inside VPCs only.
    pub(super) private: bool,
}

/// One page of the hosted zone listing.
#[derive(Debug)]
pub(super) struct ZonePage {
    /// The zones of the page.
    pub(super) zones: Vec<HostedZone>,
    /// `NextDNSName` and `NextHostedZoneId` when the listing continues.
    pub(super) next: Option<(String, String)>,
}

/// An rrset as read: the old set a conditional write repeats exactly.
// Source: API reference, `ChangeResourceRecordSets` ("To delete a resource record set, you must
// specify all the same values that you specified when you created it"); `ResourceRecord.Value`
// ("In the case of a DELETE action, if the current value does not match the actual value, an
// error is returned").
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rrset {
    /// TTL in seconds, as read.
    pub(super) ttl: u64,
    /// The values in the API's text form, as read.
    pub(super) values: Vec<String>,
}

/// What the record-level read of one name and type found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Lookup {
    /// No rrset of the name and type.
    Absent,
    /// One plain rrset.
    Plain(Rrset),
    /// An alias, a routing-policy set, or several sets of the name and type (design section
    /// 3.4): never presented as an rrset and never changed.
    NotPlain,
}

/// Where the next page of an rrset listing starts.
// Source: API reference, `ListResourceRecordSets` (`NextRecordName`, `NextRecordType`,
// `NextRecordIdentifier`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cursor {
    /// `NextRecordName`, as the API spelled it.
    name: String,
    /// `NextRecordType`.
    rtype: String,
    /// `NextRecordIdentifier`, for a routing-policy set.
    identifier: Option<String>,
}

/// One page of an rrset listing.
#[derive(Debug)]
pub(super) struct RrsetPage {
    /// The rrsets of the page.
    pub(super) sets: Vec<Listed>,
    /// Where the listing continues.
    pub(super) next: Option<Cursor>,
}

/// One rrset of a listing.
#[derive(Debug)]
pub(super) struct Listed {
    /// The owner name, `None` when it is not a valid domain name.
    pub(super) name: Option<DomainName>,
    /// The type as the API spells it.
    pub(super) rtype: String,
    /// The TTL and values of a plain rrset; `None` for an alias, a routing-policy set, or a set
    /// without its TTL or records.
    pub(super) plain: Option<Rrset>,
}

/// The action of one change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    /// Create an rrset that must not exist.
    Create,
    /// Delete an rrset that must exist with exactly these TTL and values.
    Delete,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Action::Create => "CREATE",
            Action::Delete => "DELETE",
        }
    }
}

/// One change of a batch: a whole rrset.
#[derive(Debug)]
pub(super) struct Change<'a> {
    /// The action.
    pub(super) action: Action,
    /// The owner name.
    pub(super) name: &'a DomainName,
    /// The record type, as the API spells it.
    pub(super) rtype: &'a str,
    /// The TTL.
    pub(super) ttl: u64,
    /// The values in the API's text form.
    pub(super) values: &'a [String],
}

/// The answer to a change batch.
#[derive(Debug)]
pub(super) enum Submitted {
    /// Accepted and `INSYNC`.
    Done,
    /// `404`: the hosted zone does not exist (any more).
    ZoneMissing,
    /// `InvalidChangeBatch`: the batch was refused as a whole and nothing was written. The
    /// error is the refusal; the caller reads again to tell a changed rrset from another
    /// problem.
    Invalid(Error),
}

/// The client's handle on the API: the transport, the endpoint and the keys.
pub(super) struct Api {
    http: Http,
    base: Endpoint,
    signer: Arc<Signer>,
    poller: Poller,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("base", &self.base)
            .field("access_key_id", &self.signer.access_key_id)
            .finish_non_exhaustive()
    }
}

/// Signs every attempt of a request with SigV4, right before the transport sends it, over
/// exactly what the attempt sends: its method, the `Host` derived from its URL, its path and
/// query string, and the hash of its body, with an `x-amz-date` from the clock at that moment.
/// A repeated attempt therefore carries a date of its own instead of the first attempt's.
///
/// The secret key and the session token are registered with the client's scrubber when the
/// client is built; `Authorization` and `X-Amz-Security-Token` are secret headers.
struct Signer {
    access_key_id: String,
    secret: SecretString,
    session_token: Option<SecretString>,
}

impl Finish for Signer {
    fn finish(&self, attempt: &Outgoing<'_>) -> Result<Vec<(HeaderName, HeaderValue)>, Error> {
        let unsigned = || Error::InvalidInput {
            detail: Detail::constant("the request could not be signed"),
        };
        let host = host_header(attempt.url).ok_or_else(unsigned)?;
        // Every path the client builds consists of unreserved characters and `/`, for which
        // the canonical URI (each segment encoded twice for services other than S3) is the
        // path itself.
        let path = attempt.url.path();
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~/".contains(&b))
        {
            return Err(unsigned());
        }
        // `Api::url` checked that the query string is the canonical one.
        let query = attempt.url.query().unwrap_or("");
        let payload = sigv4::payload_hash(attempt.body);
        let amz_date = jiff::Timestamp::now()
            .strftime("%Y%m%dT%H%M%SZ")
            .to_string();
        let keys = sigv4::Keys {
            access_key_id: &self.access_key_id,
            secret: &self.secret,
            session_token: self.session_token.as_ref(),
        };
        let signing = sigv4::Request {
            method: attempt.method.as_str(),
            host: &host,
            path,
            query,
            headers: &[],
            payload_hash: &payload,
        };
        let authorization: Zeroizing<String> =
            sigv4::authorization(&signing, &keys, SCOPE, &amz_date).map_err(|_| unsigned())?;
        let secret = |value: &str| sensitive_value("", value.as_bytes()).ok_or_else(unsigned);
        let mut headers = vec![
            (
                X_AMZ_DATE,
                HeaderValue::from_str(&amz_date).map_err(|_| unsigned())?,
            ),
            (AUTHORIZATION, secret(&authorization)?),
        ];
        if let Some(token) = &self.session_token {
            headers.push((X_AMZ_SECURITY_TOKEN, secret(token.expose_secret())?));
        }
        Ok(headers)
    }
}

/// `host[:port]` as the `Host` header of a request to `url` carries it: the port only when it
/// is not the scheme's default (the URL parser drops a default port).
fn host_header(url: &Url) -> Option<String> {
    match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => Some(format!("{host}:{port}")),
        (Some(host), None) => Some(host.to_owned()),
        (None, _) => None,
    }
}

/// True for a rate-limit answer: HTTP 400 with one of [`RATE_CODES`]. Registered with the
/// transport, which then treats it exactly like a 429 (design section 5.3): an idempotent read
/// is retried within the bounds with back-off, and anything else is `Error::RateLimited`. Only
/// the code is read; nothing of the body leaves this function.
pub(super) fn throttled(response: &Response) -> bool {
    response.status() == 400
        && aws_error(&response.text()).is_some_and(|(code, _)| RATE_CODES.contains(&code.as_str()))
}

impl Api {
    /// The API at `base`, signed with these keys.
    pub(super) fn new(
        http: Http,
        base: Endpoint,
        access_key_id: String,
        secret: SecretString,
        session_token: Option<SecretString>,
        poll_interval: Duration,
    ) -> Result<Api, Error> {
        if host_header(base.as_url()).is_none() {
            return Err(Error::Config {
                detail: Detail::constant("base_url is not a valid absolute URL with a host"),
            });
        }
        Ok(Api {
            http,
            base,
            signer: Arc::new(Signer {
                access_key_id,
                secret,
                session_token,
            }),
            poller: Poller::new(poll_interval, MAX_POLLS),
        })
    }

    /// A URL below the endpoint with `query`. The parameters are sorted by name, and the URL is
    /// checked to carry exactly the canonical query string, which the signer signs as it is.
    fn url(
        &self,
        path: impl FnOnce(UrlBuilder) -> UrlBuilder,
        query: &mut [(&'static str, &str)],
    ) -> Result<Url, Error> {
        query.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(b.1)));
        let mut builder = path(self.base.url());
        for (key, value) in query.iter() {
            builder = builder.query(key, value);
        }
        let url = builder.build()?;
        let canonical = sigv4::canonical_query(query);
        if url.query().unwrap_or("") != canonical {
            return Err(Error::InvalidInput {
                detail: Detail::constant("the request URL does not carry the signed query string"),
            });
        }
        Ok(url)
    }

    /// A request signed with SigV4 on every attempt ([`Signer`]). A 403 is kept for the
    /// client's own classification (signature errors are `Auth`).
    fn signed(&self, method: Method, url: Url, body: Option<Bytes>) -> Request {
        let mut request = Request::new(method, url)
            .accept(encode::XML)
            .keep_status(403)
            .finish_with(self.signer.clone());
        if let Some(body) = body {
            request = request.body(encode::XML, body);
        }
        request
    }

    /// Sends a signed `GET` (idempotent).
    async fn get(
        &self,
        path: impl FnOnce(UrlBuilder) -> UrlBuilder,
        query: &mut [(&'static str, &str)],
    ) -> Result<Response, Error> {
        let url = self.url(path, query)?;
        let request = self.signed(Method::GET, url, None).idempotent();
        self.http.send(&request).await
    }

    /// The smallest signed request that needs no zone: the first hosted zone. Verifies the
    /// keys.
    // Source: API reference, `ListHostedZonesByName` example request (`?maxitems=1`).
    pub(super) async fn probe(&self) -> Result<(), Error> {
        let response = self
            .get(
                |u| u.path("/2013-04-01/hostedzonesbyname"),
                &mut [("maxitems", "1")],
            )
            .await?;
        if response.is_success() {
            Ok(())
        } else {
            Err(self.refusal(&response))
        }
    }

    /// One page of the hosted zone listing: from the start, or from `dnsname` (and, for a
    /// later page, `hostedzoneid`).
    // Source: API reference, `ListHostedZonesByName`: `dnsname` and `hostedzoneid` (the
    // `NextDNSName` and `NextHostedZoneId` of the previous page), `maxitems`; zones sorted by
    // name with the labels reversed; `IsTruncated`, and `NextDNSName` and `NextHostedZoneId`
    // "present only if IsTruncated is true". lego (line 315) sends the zone name
    // without the trailing dot.
    pub(super) async fn zones_page(
        &self,
        dnsname: Option<&str>,
        hostedzoneid: Option<&str>,
    ) -> Result<ZonePage, Error> {
        let mut query: Vec<(&'static str, &str)> = vec![("maxitems", ZONE_PAGE)];
        if let Some(dnsname) = dnsname {
            query.push(("dnsname", dnsname));
        }
        if let Some(id) = hostedzoneid {
            query.push(("hostedzoneid", id));
        }
        let response = self
            .get(|u| u.path("/2013-04-01/hostedzonesbyname"), &mut query)
            .await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let root = doc.root_element();
        let listed = (root.tag_name().name() == "ListHostedZonesByNameResponse")
            .then(|| child(root, "HostedZones"))
            .flatten()
            .ok_or_else(|| protocol("the hosted zone listing is not in the expected form"))?;
        let zones = children(listed, "HostedZone")
            .map(hosted_zone)
            .collect::<Result<Vec<_>, _>>()?;
        let next = match child_text(root, "IsTruncated").as_deref() {
            Some("false") => None,
            Some("true") => {
                match (
                    child_text(root, "NextDNSName"),
                    child_text(root, "NextHostedZoneId"),
                ) {
                    (Some(name), Some(id)) if !name.is_empty() && !id.is_empty() => {
                        Some((name, id))
                    }
                    _ => {
                        return Err(protocol(
                            "the hosted zone listing is truncated but names no next page",
                        ));
                    }
                }
            }
            _ => {
                return Err(protocol(
                    "the hosted zone listing is not in the expected form",
                ));
            }
        };
        Ok(ZonePage { zones, next })
    }

    /// Every hosted zone, all pages (at most [`MAX_PAGES`]).
    pub(super) async fn all_zones(&self) -> Result<Vec<HostedZone>, Error> {
        let mut zones = Vec::new();
        let mut cursor: Option<(String, String)> = None;
        for _ in 0..MAX_PAGES {
            let page = match &cursor {
                None => self.zones_page(None, None).await?,
                Some((name, id)) => self.zones_page(Some(name), Some(id)).await?,
            };
            zones.extend(page.zones);
            match page.next {
                None => return Ok(zones),
                Some(next) if cursor.as_ref() == Some(&next) => {
                    return Err(protocol("the provider's pagination did not advance"));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(protocol(
            "the listing has more than 1000 pages, the limit of the client",
        ))
    }

    /// The hosted zone `id`, or `None` when the API does not know it (`404`).
    // Source: API reference, `GetHostedZone`: `NoSuchHostedZone`, HTTP 404.
    pub(super) async fn hosted_zone(&self, id: &str) -> Result<Option<HostedZone>, Error> {
        let response = self
            .get(|u| u.path("/2013-04-01/hostedzone").id(id), &mut [])
            .await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let root = doc.root_element();
        let zone = (root.tag_name().name() == "GetHostedZoneResponse")
            .then(|| child(root, "HostedZone"))
            .flatten()
            .ok_or_else(|| protocol("the hosted zone is not in the expected form"))?;
        hosted_zone(zone).map(Some)
    }

    /// The TXT rrset of `name` in zone `zone_id`, or `Stale` when the API does not know the
    /// zone (`404`).
    ///
    /// The listing starts at the given name and type and returns the next rrset in sort order
    /// when there is no exact match, so the first item's name and type are compared. An rrset
    /// with a routing policy or an alias is not plain records and is refused (design section
    /// 3.4).
    // Source: API reference, `ListResourceRecordSets`: "The results begin with the first
    // resource record set in the list whose name is greater than or equal to Name, and whose
    // type is greater than or equal to Type"; `NoSuchHostedZone`, HTTP 404; `SetIdentifier`
    // and `AliasTarget` mark routing-policy and alias sets.
    pub(super) async fn txt_rrset(
        &self,
        zone_id: &str,
        name: &DomainName,
    ) -> Result<Attempt<Option<Rrset>>, Error> {
        let response = self
            .get(
                |u| u.path("/2013-04-01/hostedzone").id(zone_id).path("/rrset"),
                &mut [("maxitems", "1"), ("name", name.as_str()), ("type", "TXT")],
            )
            .await?;
        if response.status() == 404 {
            return Ok(Attempt::Stale);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let root = doc.root_element();
        let listed = (root.tag_name().name() == "ListResourceRecordSetsResponse")
            .then(|| child(root, "ResourceRecordSets"))
            .flatten()
            .ok_or_else(|| protocol("the rrset listing is not in the expected form"))?;
        let Some(set) = children(listed, "ResourceRecordSet").next() else {
            return Ok(Attempt::Done(None));
        };
        let same_name = child_text(set, "Name")
            .and_then(|raw| owner_name(&raw))
            .is_some_and(|found| &found == name);
        if !same_name || child_text(set, "Type").as_deref() != Some("TXT") {
            return Ok(Attempt::Done(None));
        }
        if !is_plain(set) {
            return Err(Error::Rejected {
                status: None,
                detail: Detail::constant(
                    "the TXT rrset uses a routing policy or is an alias; it is not changed",
                ),
            });
        }
        plain_rrset(set).map(|rrset| Attempt::Done(Some(rrset)))
    }

    /// The rrset of `name` and `rtype` in zone `zone_id` (record level), or `Stale` when the
    /// API does not know the zone (`404`).
    ///
    /// Two items are requested: the listing starts at the given name and type, so the first
    /// item is the rrset if there is one, and a second item of the same name and type means
    /// several sets share them (routing-policy sets), which is not a plain rrset, whatever the
    /// first one carries.
    // Source: API reference, `ListResourceRecordSets` (start position, `maxitems`, `404
    // NoSuchHostedZone`); `ResourceRecordSet.SetIdentifier`: "differentiates among multiple
    // resource record sets that have the same combination of name and type".
    pub(super) async fn rrset_at(
        &self,
        zone_id: &str,
        name: &DomainName,
        rtype: &str,
    ) -> Result<Attempt<Lookup>, Error> {
        let response = self
            .get(
                |u| u.path("/2013-04-01/hostedzone").id(zone_id).path("/rrset"),
                &mut [("maxitems", "2"), ("name", name.as_str()), ("type", rtype)],
            )
            .await?;
        if response.status() == 404 {
            return Ok(Attempt::Stale);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let listed = listed_sets(&doc)?;
        let matching: Vec<roxmltree::Node<'_, '_>> = children(listed, "ResourceRecordSet")
            .take_while(|set| {
                child_text(*set, "Type").as_deref() == Some(rtype)
                    && child_text(*set, "Name")
                        .and_then(|raw| owner_name(&raw))
                        .is_some_and(|found| &found == name)
            })
            .collect();
        Ok(Attempt::Done(match matching.as_slice() {
            [] => Lookup::Absent,
            [set] if is_plain(*set) => Lookup::Plain(plain_rrset(*set)?),
            _ => Lookup::NotPlain,
        }))
    }

    /// One page of the rrset listing of zone `zone_id`, from the start or from `cursor`, or
    /// `Stale` when the API does not know the zone (`404`).
    // Source: API reference, `ListResourceRecordSets`: `name`, `type` and `identifier` take
    // the `NextRecordName`, `NextRecordType` and `NextRecordIdentifier` of the previous page;
    // `IsTruncated`; `NextRecordName` and `NextRecordType` are "present only if IsTruncated is
    // true"; at most 300 rrsets per page.
    pub(super) async fn rrset_page(
        &self,
        zone_id: &str,
        cursor: Option<&Cursor>,
    ) -> Result<Attempt<RrsetPage>, Error> {
        let mut query: Vec<(&'static str, &str)> = vec![("maxitems", RRSET_PAGE)];
        if let Some(cursor) = cursor {
            query.push(("name", &cursor.name));
            query.push(("type", &cursor.rtype));
            if let Some(identifier) = &cursor.identifier {
                query.push(("identifier", identifier));
            }
        }
        let response = self
            .get(
                |u| u.path("/2013-04-01/hostedzone").id(zone_id).path("/rrset"),
                &mut query,
            )
            .await?;
        if response.status() == 404 {
            return Ok(Attempt::Stale);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let listed = listed_sets(&doc)?;
        let mut sets = Vec::new();
        for set in children(listed, "ResourceRecordSet") {
            let rtype = child_text(set, "Type")
                .filter(|t| !t.is_empty())
                .ok_or_else(|| protocol("a listed rrset has no type"))?;
            let raw_name =
                child_text(set, "Name").ok_or_else(|| protocol("a listed rrset has no name"))?;
            // A set that is not plain, or that lacks its TTL or records, is reported as one
            // the model cannot hold; it never fails the listing (design section 3.4).
            let plain = if is_plain(set) {
                plain_rrset(set).ok()
            } else {
                None
            };
            sets.push(Listed {
                name: owner_name(&raw_name),
                rtype,
                plain,
            });
        }
        let root = doc.root_element();
        let next = match child_text(root, "IsTruncated").as_deref() {
            Some("false") => None,
            Some("true") => match (
                child_text(root, "NextRecordName"),
                child_text(root, "NextRecordType"),
            ) {
                (Some(name), Some(rtype)) if !name.is_empty() && !rtype.is_empty() => {
                    Some(Cursor {
                        name,
                        rtype,
                        identifier: child_text(root, "NextRecordIdentifier")
                            .filter(|id| !id.is_empty()),
                    })
                }
                _ => {
                    return Err(protocol(
                        "the rrset listing is truncated but names no next page",
                    ));
                }
            },
            _ => return Err(protocol("the rrset listing is not in the expected form")),
        };
        Ok(Attempt::Done(RrsetPage { sets, next }))
    }

    /// Every rrset of zone `zone_id`, all pages (at most [`MAX_PAGES`]), or `Stale` when the
    /// API does not know the zone. A page that does not advance, or a listing longer than the
    /// limit, is `Error::Protocol`, never a shorter list (design section 3.4).
    pub(super) async fn all_rrsets(&self, zone_id: &str) -> Result<Attempt<Vec<Listed>>, Error> {
        let mut sets = Vec::new();
        let mut cursor: Option<Cursor> = None;
        for _ in 0..MAX_PAGES {
            let page = match self.rrset_page(zone_id, cursor.as_ref()).await? {
                Attempt::Done(page) => page,
                Attempt::Stale => return Ok(Attempt::Stale),
            };
            sets.extend(page.sets);
            match page.next {
                None => return Ok(Attempt::Done(sets)),
                Some(next) if cursor.as_ref() == Some(&next) => {
                    return Err(protocol("the provider's pagination did not advance"));
                }
                Some(next) => cursor = Some(next),
            }
        }
        Err(protocol(
            "the listing has more than 1000 pages, the limit of the client",
        ))
    }

    /// Submits a change batch and waits until it is `INSYNC`. Sent once: a change is not
    /// repeated automatically (design section 5.3); the batch carries its own condition
    /// (`DELETE` of the old set as read).
    // Source: API reference, `ChangeResourceRecordSets`: `POST
    // /2013-04-01/hostedzone/{Id}/rrset/`; "Route 53 validates the changes in the request and
    // then either makes all or none of the changes"; `InvalidChangeBatch` (400),
    // `NoSuchHostedZone` (404), `PriorRequestNotComplete` (400); the answer's `ChangeInfo`
    // with `Id` and `Status`.
    pub(super) async fn change(
        &self,
        zone_id: &str,
        changes: &[Change<'_>],
    ) -> Result<Submitted, Error> {
        let url = self.url(
            |u| u.path("/2013-04-01/hostedzone").id(zone_id).path("/rrset/"),
            &mut [],
        )?;
        let body = Bytes::from(change_batch(changes).into_bytes());
        let request = self.signed(Method::POST, url, Some(body));
        let response = self.http.send(&request).await?;
        if response.status() == 404 {
            return Ok(Submitted::ZoneMissing);
        }
        if response.status() == 400
            && let Some(messages) = self.invalid_change_batch(&response)
        {
            return Ok(Submitted::Invalid(Error::Rejected {
                status: Some(400),
                detail: messages,
            }));
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        // The batch was accepted: from here on, an answer the client cannot read leaves the
        // outcome unknown, which is `Transient`, not `Protocol` (design section 3.7).
        let Some((id, insync)) = accepted_change(&response.text()) else {
            return Err(Error::Transient {
                detail: Detail::constant(
                    "the provider accepted the change, but its answer does not name the change \
                     in the expected form; the outcome is unknown",
                ),
            });
        };
        if insync {
            return Ok(Submitted::Done);
        }
        self.poller.run(|| self.change_status(&id)).await?;
        Ok(Submitted::Done)
    }

    /// One look at a change: `PENDING` or `INSYNC`.
    // Source: API reference, `GetChange`: `GET /2013-04-01/change/{Id}`; "PENDING indicates that
    // the changes in this request have not propagated"; "INSYNC indicates that the changes have
    // propagated to all Route 53 DNS servers"; `NoSuchChange`, 404.
    async fn change_status(&self, id: &str) -> Result<PollStep<()>, Error> {
        let response = self
            .get(|u| u.path("/2013-04-01/change").id(id), &mut [])
            .await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        let text = response.text();
        let doc = parse(&text)?;
        let root = doc.root_element();
        let status = (root.tag_name().name() == "GetChangeResponse")
            .then(|| child(root, "ChangeInfo"))
            .flatten()
            .and_then(|info| child_text(info, "Status"));
        Ok(match status.as_deref() {
            Some(INSYNC) => PollStep::Done(()),
            Some(PENDING) => PollStep::Pending,
            _ => PollStep::Failed(protocol("the change status is not in the expected form")),
        })
    }

    /// The messages of an `InvalidChangeBatch` answer, scrubbed, or `None` for another answer.
    // Source: API reference, `ChangeResourceRecordSets` errors: `InvalidChangeBatch`, "a list of
    // messages", HTTP 400. Assumption (not documented): the body's root element is
    // `InvalidChangeBatch` with `Messages/Message`; a body of another shape is classified as an
    // ordinary refusal, which never writes again.
    fn invalid_change_batch(&self, response: &Response) -> Option<Detail> {
        let scrubbed = self.http.scrubber().scrub(&response.text());
        let doc = roxmltree::Document::parse(&scrubbed).ok()?;
        let root = doc.root_element();
        let code_is_batch = root
            .descendants()
            .find(|n| n.tag_name().name() == "Code")
            .and_then(|n| n.text())
            .is_some_and(|code| code.trim() == "InvalidChangeBatch");
        if root.tag_name().name() != "InvalidChangeBatch" && !code_is_batch {
            return None;
        }
        let messages: Vec<&str> = root
            .descendants()
            .filter(|n| n.tag_name().name() == "Message")
            .filter_map(|n| n.text())
            .map(message_head)
            .collect();
        let text = if messages.is_empty() {
            "InvalidChangeBatch".to_owned()
        } else {
            format!("InvalidChangeBatch: {}", messages.join("; "))
        };
        Some(self.http.detail(&text))
    }

    /// An answer the client does not expect, classified by its error code. The whole body is
    /// scrubbed before it is parsed (design section 5.5); a signature error contributes the
    /// first sentence of its message only.
    pub(super) fn refusal(&self, response: &Response) -> Error {
        let status = response.status();
        let scrubbed = self.http.scrubber().scrub(&response.text());
        let parsed = aws_error(&scrubbed);
        let code = parsed.as_ref().map(|(code, _)| code.as_str()).unwrap_or("");
        let message = parsed.as_ref().map(|(_, m)| m.as_str()).unwrap_or("");
        let clock = CLOCK_CODES.contains(&code)
            || CLOCK_MESSAGES
                .iter()
                .any(|m| message.trim_start().starts_with(m));
        let auth = clock || AUTH_CODES.contains(&code);
        let detail = match &parsed {
            Some((code, message)) => {
                let head = if auth {
                    first_sentence(message)
                } else {
                    message_head(message)
                };
                let mut text = if head.is_empty() {
                    code.clone()
                } else {
                    format!("{code}: {head}")
                };
                if clock {
                    text.push_str("; ");
                    text.push_str(CLOCK_HINT);
                }
                self.http.detail(&text)
            }
            None => self.http.body_detail(response),
        };
        match status {
            403 if auth => Error::Auth { detail },
            401 => Error::Auth { detail },
            403 => Error::Forbidden { detail },
            400 if RATE_CODES.contains(&code) => Error::RateLimited { retry_after: None },
            400 if auth => Error::Auth { detail },
            400 | 404 | 409 => Error::Rejected {
                status: Some(status),
                detail,
            },
            _ => Error::Protocol {
                detail: self.http.detail(&format!("status {status}: {detail}")),
            },
        }
    }
}

/// The change ID (without the prefix, checked by [`path_id`]) and whether it is `INSYNC`
/// already, from the answer to an accepted batch; `None` for an answer of another form.
// Source: API reference, `ChangeResourceRecordSets` response: `ChangeInfo` with `Id` and
// `Status`.
fn accepted_change(text: &str) -> Option<(String, bool)> {
    let doc = roxmltree::Document::parse(text).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "ChangeResourceRecordSetsResponse" {
        return None;
    }
    let info = child(root, "ChangeInfo")?;
    let id = child_text(info, "Id")?;
    let id = id.strip_prefix(CHANGE_PREFIX).unwrap_or(&id);
    let id = path_id(id).ok()?.to_owned();
    Some((id, child_text(info, "Status").as_deref() == Some(INSYNC)))
}

/// The prefix of a change ID in `ChangeInfo.Id`.
// Source: API reference, `ChangeInfo.Id` is the value `GetChange` takes; the AWS SDK and lego
// pass it on as returned. Assumption (not documented): it may carry the prefix `/change/`, as
// `HostedZone.Id` carries `/hostedzone/`; stripping a prefix that is absent changes nothing.
const CHANGE_PREFIX: &str = "/change/";

/// The statuses of a change.
// Source: API reference, `GetChange`.
const PENDING: &str = "PENDING";
const INSYNC: &str = "INSYNC";

/// The body of `ChangeResourceRecordSets`. Every value goes through the one XML escaping
/// function; element names are constants.
// Source: API reference, `ChangeResourceRecordSets`, "Basic Syntax" example: `ChangeBatch`,
// `Changes`, `Change` with `Action` and `ResourceRecordSet` (`Name`, `Type`, `TTL`,
// `ResourceRecords` of `ResourceRecord` with `Value`), in that order.
pub(super) fn change_batch(changes: &[Change<'_>]) -> String {
    let mut xml = XmlWriter::new();
    xml.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.open_with_namespace("ChangeResourceRecordSetsRequest", XMLNS);
    xml.open("ChangeBatch");
    xml.open("Changes");
    for change in changes {
        xml.open("Change");
        xml.element("Action", change.action.as_str());
        xml.open("ResourceRecordSet");
        xml.element("Name", change.name.as_str());
        xml.element("Type", change.rtype);
        xml.element("TTL", &change.ttl.to_string());
        xml.open("ResourceRecords");
        for value in change.values {
            xml.open("ResourceRecord");
            xml.element("Value", value);
            xml.close("ResourceRecord");
        }
        xml.close("ResourceRecords");
        xml.close("ResourceRecordSet");
        xml.close("Change");
    }
    xml.close("Changes");
    xml.close("ChangeBatch");
    xml.close("ChangeResourceRecordSetsRequest");
    xml.finish()
}

/// Builds XML from constant element names and escaped text.
struct XmlWriter(String);

impl XmlWriter {
    fn new() -> XmlWriter {
        XmlWriter(String::new())
    }

    fn raw(&mut self, text: &'static str) {
        self.0.push_str(text);
    }

    fn open(&mut self, tag: &'static str) {
        self.0.push('<');
        self.0.push_str(tag);
        self.0.push('>');
    }

    fn open_with_namespace(&mut self, tag: &'static str, namespace: &'static str) {
        self.0.push('<');
        self.0.push_str(tag);
        self.0.push_str(" xmlns=\"");
        self.0.push_str(&xml_escape(namespace));
        self.0.push_str("\">");
    }

    fn close(&mut self, tag: &'static str) {
        self.0.push_str("</");
        self.0.push_str(tag);
        self.0.push('>');
    }

    fn element(&mut self, tag: &'static str, text: &str) {
        self.open(tag);
        self.0.push_str(&xml_escape(text));
        self.close(tag);
    }

    fn finish(self) -> String {
        self.0
    }
}

/// An owner name as the API returns it, as a [`DomainName`]: lowercase, with the trailing dot.
/// The API returns every character other than `a-z`, `0-9`, `-` and `_` as a `\ooo` octal
/// escape; each escape is decoded, and the result must be a valid owner name (design section
/// 2.1), of which the only such character is the wildcard `*` (`\052`) as the leftmost label.
/// A backslash that does not start three octal digits, an escaped dot or octet outside printable
/// ASCII, or a name [`DomainName::parse`] refuses yields `None`.
// Source: Developer Guide, "DNS domain name format"
// (https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DomainNameFormat.html): "Route 53
// stores alphabetic characters as lowercase letters"; "If the domain name includes any
// characters other than a to z, 0 to 9, - (hyphen), or _ (underscore), Route 53 API actions
// return the characters as escape codes".
pub(super) fn owner_name(raw: &str) -> Option<DomainName> {
    let mut text = String::with_capacity(raw.len());
    let mut chars = raw.trim().chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            text.push(c);
            continue;
        }
        let mut value: u32 = 0;
        for _ in 0..3 {
            value = value * 8 + chars.next()?.to_digit(8)?;
        }
        // A decoded `.` is an octet of a label, not a separator; `DomainName` cannot hold it.
        let octet = u8::try_from(value)
            .ok()
            .filter(|b| b.is_ascii_graphic() && *b != b'.')?;
        text.push(char::from(octet));
    }
    DomainName::parse(&text).ok()
}

/// The `ResourceRecordSets` element of a `ListResourceRecordSetsResponse`.
fn listed_sets<'a, 'i>(doc: &'a roxmltree::Document<'i>) -> Result<roxmltree::Node<'a, 'i>, Error> {
    let root = doc.root_element();
    (root.tag_name().name() == "ListResourceRecordSetsResponse")
        .then(|| child(root, "ResourceRecordSets"))
        .flatten()
        .ok_or_else(|| protocol("the rrset listing is not in the expected form"))
}

/// True for a set without any of the [`NOT_PLAIN`] elements.
fn is_plain(set: roxmltree::Node<'_, '_>) -> bool {
    !NOT_PLAIN.iter().any(|tag| child(set, tag).is_some())
}

/// The TTL and the values of a plain rrset, as the API returned them.
fn plain_rrset(set: roxmltree::Node<'_, '_>) -> Result<Rrset, Error> {
    let ttl = child_text(set, "TTL")
        .and_then(|t| t.parse::<u64>().ok())
        .ok_or_else(|| protocol("the rrset has no TTL"))?;
    let records =
        child(set, "ResourceRecords").ok_or_else(|| protocol("the rrset has no records"))?;
    let values = children(records, "ResourceRecord")
        .map(|record| {
            child(record, "Value")
                .map(|value| value.text().unwrap_or("").to_owned())
                .ok_or_else(|| protocol("a record has no value"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Rrset { ttl, values })
}

/// A hosted zone element.
fn hosted_zone(node: roxmltree::Node<'_, '_>) -> Result<HostedZone, Error> {
    let id = child_text(node, "Id")
        .and_then(|raw| zone_id(&raw))
        .ok_or_else(|| protocol("the provider returned a hosted zone ID of an unexpected form"))?;
    let name = child_text(node, "Name").ok_or_else(|| protocol("a hosted zone has no name"))?;
    // Lego reads `Config.PrivateZone` of every listed zone; a zone without it is not a
    // complete answer.
    let private = match child(node, "Config").and_then(|c| child_text(c, "PrivateZone")) {
        Some(flag) if flag == "true" => true,
        Some(flag) if flag == "false" => false,
        _ => return Err(protocol("a hosted zone does not say whether it is private")),
    };
    Ok(HostedZone {
        id,
        name: owner_name(&name),
        private,
    })
}

/// The error code and message of an error answer: the first `Code` and `Message` elements, or
/// the messages of an `InvalidChangeBatch`. `None` when the body is not XML or has no code.
// Source: API reference, Common errors (codes); `ChangeResourceRecordSets` (`InvalidChangeBatch`
// with messages). Assumption (not documented): the codes and messages are carried in `Code`
// and `Message` elements (`ErrorResponse/Error/{Code, Message}`, as the Quotas page names a
// "Code element" and a "Message element"); a body of another shape falls back to the start of
// the body.
fn aws_error(body: &str) -> Option<(String, String)> {
    let doc = roxmltree::Document::parse(body).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() == "InvalidChangeBatch" {
        let messages: Vec<&str> = root
            .descendants()
            .filter(|n| n.tag_name().name() == "Message")
            .filter_map(|n| n.text())
            .collect();
        return Some(("InvalidChangeBatch".to_owned(), messages.join("; ")));
    }
    let text = |tag: &str| {
        root.descendants()
            .find(|n| n.tag_name().name() == tag)
            .and_then(|n| n.text())
            .map(|t| t.trim().to_owned())
    };
    let code = text("Code").filter(|c| !c.is_empty())?;
    Some((code, text("Message").unwrap_or_default()))
}

/// The provider's error message for the transport's own error texts (401, 5xx): the code and
/// the message without the part that repeats the canonical request. `None` when the body is
/// not an error document.
pub(super) fn error_message(body: &str) -> Option<String> {
    let (code, message) = aws_error(body)?;
    let head = if AUTH_CODES.contains(&code.as_str()) {
        first_sentence(&message)
    } else {
        message_head(&message)
    };
    Some(if head.is_empty() {
        code
    } else {
        format!("{code}: {head}")
    })
}

/// The message before the part that repeats the canonical request or the string to sign.
fn message_head(message: &str) -> &str {
    let end = CANONICAL_MARKERS
        .iter()
        .filter_map(|marker| message.find(marker))
        .min()
        .unwrap_or(message.len());
    message.get(..end).unwrap_or("").trim()
}

/// The first sentence of the message (through the first `. `), before any canonical request.
fn first_sentence(message: &str) -> &str {
    let head = message_head(message);
    match head.find(". ") {
        Some(end) => head.get(..=end).unwrap_or(head),
        None => head,
    }
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
    fn error_messages_drop_the_canonical_request() {
        let body = "<ErrorResponse><Error><Type>Sender</Type><Code>SignatureDoesNotMatch</Code>\
             <Message>The request signature we calculated does not match the signature you \
             provided. Check your key.\n\nThe Canonical String for this request should have \
             been\n'GET\n/\n\nx-amz-security-token:tok-canary\n'</Message></Error></ErrorResponse>";
        assert_eq!(
            error_message(body).unwrap(),
            "SignatureDoesNotMatch: The request signature we calculated does not match the \
             signature you provided."
        );
        let body = "<ErrorResponse><Error><Code>InvalidInput</Code><Message>bad. very bad\
             </Message></Error></ErrorResponse>";
        assert_eq!(error_message(body).unwrap(), "InvalidInput: bad. very bad");
        let batch = "<InvalidChangeBatch><Messages><Message>a</Message><Message>b</Message>\
             </Messages></InvalidChangeBatch>";
        assert_eq!(error_message(batch).unwrap(), "InvalidChangeBatch: a; b");
        assert_eq!(error_message("{\"message\":\"x\"}"), None);
        assert_eq!(message_head("a. b\n\nThe String-to-Sign x"), "a. b");
    }

    #[test]
    fn owner_names_decode_octal_escapes() {
        assert_eq!(
            owner_name("_acme-challenge.example.org.").unwrap().as_str(),
            "_acme-challenge.example.org."
        );
        assert_eq!(
            owner_name("\\052.example.org.").unwrap().as_str(),
            "*.example.org."
        );
        assert_eq!(
            owner_name("\\141\\142.example.org.").unwrap().as_str(),
            "ab.example.org."
        );
        // Not a valid owner name, or not an octal escape.
        assert!(owner_name("a\\052b.example.org.").is_none());
        assert!(owner_name("a\\056b.example.org.").is_none());
        assert!(owner_name("a\\.b.example.org.").is_none());
        assert!(owner_name("a\\08b.example.org.").is_none());
        assert!(owner_name("a\\400.example.org.").is_none());
        assert!(owner_name("a\\040.example.org.").is_none());
        assert!(owner_name("a\\05").is_none());
    }

    #[test]
    fn change_batches_escape_every_value() {
        let name = DomainName::parse("_acme-challenge.example.org").unwrap();
        let values = ["\"a<b&c\"".to_owned()];
        let xml = change_batch(&[Change {
            action: Action::Delete,
            name: &name,
            rtype: "TXT",
            ttl: 300,
            values: &values,
        }]);
        assert!(xml.contains("<Action>DELETE</Action>"), "{xml}");
        assert!(xml.contains("<TTL>300</TTL>"), "{xml}");
        assert!(
            xml.contains("<Value>&quot;a&lt;b&amp;c&quot;</Value>"),
            "{xml}"
        );
        let doc = roxmltree::Document::parse(&xml).unwrap();
        assert_eq!(doc.root_element().tag_name().namespace(), Some(XMLNS));
    }
}
