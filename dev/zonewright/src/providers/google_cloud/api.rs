//! The Cloud DNS API and the OAuth 2.0 token endpoint as this client uses them: the JWT
//! exchange, one function per endpoint, the wire types, paging, change polling and the
//! classification of answers. Nothing here knows the value layer or the zone cache;
//! `client.rs`, `rrset.rs`, `txt.rs` and `records.rs` build on these calls.
//!
//! Sources (hard rule 3):
//!
//! - [Service account flow]: the JWT (header `alg` RS256, the only supported value, `typ` JWT,
//!   optional `kid` the key's `private_key_id`; claims `iss` the service account's e-mail,
//!   `scope` space-delimited, `aud` the token endpoint, `exp` at most one hour after `iat`), the
//!   token request (`POST`, form body with `grant_type` and `assertion`) and its answer
//!   (`access_token`, `token_type`, `expires_in`); errors carry `error` and
//!   `error_description`.
//! - [RFC 6749 section 5.2]: a token endpoint answers an error with `400` unless specified
//!   otherwise.
//! - [Discovery document] (revision 20261111): the method paths, the parameters of
//!   `managedZones.list` (`dnsName`, `pageToken`), `managedZones.get`,
//!   `resourceRecordSets.list` (`name`, `type`, `pageToken`), `changes.create`, `changes.get`,
//!   the `ManagedZone`, `ResourceRecordSet` and `Change` schemas, and the scopes.
//! - [Changes]: "A Change represents a set of ResourceRecordSet additions and deletions applied
//!   atomically to a ManagedZone"; `deletions`: "Must match existing data exactly"; `status`
//!   `pending` or `done`.
//! - [Error messages]: the reasons (`alreadyExists`, `notFound`, `preconditionFailed`,
//!   `quotaExceeded`, `invalidValue`, ...).
//! - [AIP-193]: the error body `{"error": {"code", "message", "status", "details"}}`; `NOT_FOUND`
//!   is 404, `PERMISSION_DENIED` 403, `RESOURCE_EXHAUSTED` 429.
//! - [Quotas]: "an API request returns HTTP 413" when a quota is exceeded.
//! - lego `providers/dns/gcloud/googlecloud.go` (lines cited where used).
//!
//! Endpoints used, below `{dns_url}/projects/{project}`:
//!
//! | Call               | Request                                                 | Success      |
//! | ------------------ | ------------------------------------------------------- | ------------ |
//! | token              | `POST {token_url}` form `grant_type`, `assertion`       | 200, token   |
//! | list zones         | `GET /managedZones?dnsName&pageToken`                   | 200, page    |
//! | get zone           | `GET /managedZones/{zone}`                              | 200, zone    |
//! | list rrsets        | `GET /managedZones/{zone}/rrsets?name&type&pageToken`   | 200, page    |
//! | create change      | `POST /managedZones/{zone}/changes`                     | 200, change  |
//! | get change         | `GET /managedZones/{zone}/changes/{change}`             | 200, change  |
//!
//! [Service account flow]: https://developers.google.com/identity/protocols/oauth2/service-account
//! [RFC 6749 section 5.2]: https://www.rfc-editor.org/rfc/rfc6749#section-5.2
//! [Discovery document]: https://www.googleapis.com/discovery/v1/apis/dns/v1/rest
//! [Changes]: https://docs.cloud.google.com/dns/docs/reference/rest/v1/changes
//! [Error messages]: https://docs.cloud.google.com/dns/docs/error-messages
//! [AIP-193]: https://google.aip.dev/193
//! [Quotas]: https://docs.cloud.google.com/dns/quotas

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Method, Url};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::crypto::Rs256Key;
use crate::error::Error;
use crate::http::pager::{self, Page};
use crate::http::{
    Endpoint, Http, PollStep, Poller, Request, Response, Token, TokenAuth, TokenSource, path_id,
};
use crate::redact::{Detail, SecretSlot};

/// Lifetime of a signed JWT: the documented maximum.
// Source: Service account flow (`exp`: "maximum of 1 hour after the issued time").
const JWT_LIFETIME_S: i64 = 3600;

/// The scope the token is requested for: read and write of the DNS records, the scope lego and
/// dns-update request with a service account key.
// Source: Discovery document (`auth.oauth2.scopes`: "View and manage your DNS records hosted by
// Google Cloud DNS"; `changes.create` accepts it); lego googlecloud.go:433
// (`gdns.NdevClouddnsReadwriteScope`).
const SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

/// The grant type of the token request.
// Source: Service account flow ("urn:ietf:params:oauth:grant-type:jwt-bearer").
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Most looks at one pending change (design section 3.7). With the default interval of one
/// second this waits two minutes, the time the monitoring page names for an update to reach the
/// name servers (https://docs.cloud.google.com/dns/docs/monitoring: "should happen within 120
/// seconds").
pub(super) const MAX_POLLS: u32 = 120;

/// A change's status once it is applied.
// Source: Discovery document (`Change.status`: `pending`, `done`).
const DONE: &str = "done";
const PENDING: &str = "pending";

/// A managed zone as `managedZones.list` and `managedZones.get` return it; other fields are
/// ignored. No member is required: the schema has no required list.
// Source: Discovery document, `ManagedZone`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ManagedZone {
    /// "Unique identifier for the resource; defined by the server".
    #[serde(default)]
    id: Option<String>,
    /// "User assigned name for this resource. Must be unique within the project."
    #[serde(default)]
    name: Option<String>,
    /// "The DNS name of this managed zone, for instance "example.com."".
    #[serde(default)]
    pub(super) dns_name: Option<String>,
    /// `public` or `private`.
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    private_visibility_config: Option<Value>,
    #[serde(default)]
    forwarding_config: Option<Value>,
    #[serde(default)]
    peering_config: Option<Value>,
    #[serde(default)]
    reverse_lookup_config: Option<Value>,
    #[serde(default)]
    service_directory_config: Option<Value>,
}

impl ManagedZone {
    /// The zone holds public records the client may use: its `visibility` is `public` ("records
    /// in this zone can be queried from the public internet"), and it neither forwards nor peers
    /// queries nor answers reverse lookups or service directory names on behalf of something
    /// else.
    // Source: Discovery document, `ManagedZone.visibility` ("public zones are exposed to the
    // Internet, while private zones are visible only to Virtual Private Cloud resources") and
    // the descriptions of `forwardingConfig`, `peeringConfig`, `reverseLookupConfig` and
    // `serviceDirectoryConfig`. Assumption (lego googlecloud.go:350 does the same; not observed
    // against the live API): a zone without `visibility` is public unless it carries a
    // `privateVisibilityConfig`. Assumption, conservative: a zone with any of the four
    // configurations is not used, whatever its visibility; whether such a zone accepts record
    // writes is not documented.
    pub(super) fn usable(&self) -> bool {
        let public = match self.visibility.as_deref() {
            Some(visibility) => visibility == "public",
            None => self.private_visibility_config.is_none(),
        };
        public
            && self.forwarding_config.is_none()
            && self.peering_config.is_none()
            && self.reverse_lookup_config.is_none()
            && self.service_directory_config.is_none()
    }

    /// The text the zone is addressed by in a path: its ID, or its name when the answer has no
    /// ID ("Can be the managed zone name or ID", every `managedZone` path parameter). An ID
    /// changes when the zone is deleted and created again, a name may not, so the ID is
    /// preferred: a stale cache entry then meets a `404`.
    pub(super) fn address(&self) -> Result<String, Error> {
        let text = self
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .or(self.name.as_deref())
            .unwrap_or_default();
        path_id(text).map(str::to_owned)
    }
}

/// One page of `managedZones.list`. `nextPageToken` absent or empty is the last page.
// Source: Discovery document, `ManagedZonesListResponse`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ZonePage {
    #[serde(default)]
    managed_zones: Vec<ManagedZone>,
    #[serde(default)]
    next_page_token: Option<String>,
}

/// One page of `resourceRecordSets.list`. The rrsets are kept as JSON objects; the layers
/// interpret them. A page without `rrsets` is an empty page.
// Source: Discovery document, `ResourceRecordSetsListResponse` (`rrsets`, `nextPageToken`).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RrsetPage {
    #[serde(default)]
    rrsets: Vec<Value>,
    #[serde(default)]
    next_page_token: Option<String>,
}

/// A change as `changes.create` and `changes.get` return it; other fields are ignored.
// Source: Discovery document, `Change` (`id`, `status`).
#[derive(Debug, Deserialize)]
struct Change {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// The body of `changes.create`.
// Source: Discovery document, `Change` (`additions`, `deletions`).
#[derive(Serialize)]
struct NewChange<'a> {
    additions: &'a [Value],
    deletions: &'a [Value],
}

/// The answer to a change.
#[derive(Debug)]
pub(super) enum Written {
    /// The change is applied: its status is `done`.
    Done,
    /// The provider refused the change and nothing was written. `not_found` is true for a
    /// `404`, which can mean that the zone identifier went stale. The caller reads again before
    /// it concludes anything: which status a failed deletion match produces is not documented.
    Refused {
        /// The refusal as the error it maps to.
        error: Error,
        /// The refusal was a `404`.
        not_found: bool,
    },
}

/// Signs the JWTs that are exchanged for access tokens.
struct Signer {
    key: Rs256Key,
    /// `iss`: the service account's e-mail address.
    client_email: SecretString,
    /// `kid`: the key's ID, if the key file has one.
    key_id: Option<SecretString>,
    /// `aud`: the token endpoint the JWT is sent to.
    audience: String,
    /// The scrubber slot of the signed JWTs.
    slot: SecretSlot,
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'static str,
    aud: &'a str,
    exp: i64,
    iat: i64,
}

impl Signer {
    /// A signed JWT for `now` (Unix seconds), in a zeroizing buffer.
    fn jwt(&self, now: i64) -> Result<Zeroizing<String>, Error> {
        let header = JwtHeader {
            alg: "RS256",
            typ: "JWT",
            kid: self
                .key_id
                .as_ref()
                .map(|kid| kid.expose_secret())
                .filter(|kid| !kid.is_empty()),
        };
        let claims = JwtClaims {
            iss: self.client_email.expose_secret(),
            scope: SCOPE,
            aud: &self.audience,
            exp: now.saturating_add(JWT_LIFETIME_S),
            iat: now,
        };
        let fail = || Error::InvalidInput {
            detail: Detail::constant("the JWT could not be encoded"),
            code: None,
        };
        let header = Zeroizing::new(serde_json::to_vec(&header).map_err(|_| fail())?);
        let claims = Zeroizing::new(serde_json::to_vec(&claims).map_err(|_| fail())?);
        let mut jwt = Zeroizing::new(String::new());
        URL_SAFE_NO_PAD.encode_string(&*header, &mut jwt);
        jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(&*claims, &mut jwt);
        let signature = self.key.sign(jwt.as_bytes()).map_err(|_| Error::Config {
            detail: Detail::constant("the JWT could not be signed with the service account key"),
        })?;
        jwt.push('.');
        URL_SAFE_NO_PAD.encode_string(&signature, &mut jwt);
        Ok(jwt)
    }
}

/// The client's handle on the APIs: the transport, the endpoints, the signer and the token.
pub(super) struct Api {
    http: Http,
    dns: Endpoint,
    token: Url,
    project: String,
    signer: Signer,
    tokens: TokenSource,
    pub(super) poller: Poller,
}

impl fmt::Debug for Api {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Api")
            .field("dns", &self.dns)
            .field("project", &self.project)
            .field("poller", &self.poller)
            .finish_non_exhaustive()
    }
}

/// What the API handle is built from.
pub(super) struct Parts {
    /// The transport handle.
    pub(super) http: Http,
    /// The Cloud DNS API.
    pub(super) dns: Endpoint,
    /// The token endpoint.
    pub(super) token: Endpoint,
    /// The project.
    pub(super) project: String,
    /// The signing key.
    pub(super) key: Rs256Key,
    /// The service account's e-mail address.
    pub(super) client_email: SecretString,
    /// The key's ID.
    pub(super) key_id: Option<SecretString>,
    /// Interval between two looks at a pending change.
    pub(super) poll_interval: Duration,
}

impl Api {
    /// The APIs of `parts`.
    pub(super) fn new(parts: Parts) -> Api {
        let token = parts.token.as_url().clone();
        Api {
            http: parts.http,
            dns: parts.dns,
            project: parts.project,
            signer: Signer {
                key: parts.key,
                client_email: parts.client_email,
                key_id: parts.key_id,
                // The documentation names the token URL as the audience; the configured token
                // endpoint is that URL unless the client is pointed at a test server.
                audience: token.as_str().to_owned(),
                slot: SecretSlot::new(),
            },
            token,
            // The token's lifetime comes with it (`expires_in`); the cache renews it ahead of
            // time.
            tokens: TokenSource::new(None),
            poller: Poller::new(parts.poll_interval, MAX_POLLS),
        }
    }

    /// The token exchange: signs a JWT, registers it with the scrubber before it is sent, and
    /// exchanges it for an access token. The token request is idempotent (design section 5.3).
    ///
    /// Answers: 2xx with `access_token` is the token, its lifetime from `expires_in`; 400 (and
    /// 401) is `Error::Auth`; 403, 429 and 5xx follow the shared mapping; anything else is a
    /// refusal.
    // Source: Service account flow (the request, `access_token`, `expires_in`; errors such as
    // `invalid_grant` for a bad signature, a deleted or disabled key, a malformed JWT or clock
    // skew); RFC 6749 section 5.2 (`400`).
    async fn fetch(&self) -> Result<Token, Error> {
        #[derive(Deserialize)]
        struct Issued {
            #[serde(default)]
            access_token: Option<String>,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let jwt = self.signer.jwt(jiff::Timestamp::now().as_second())?;
        self.http.remember(&self.signer.slot, jwt.as_str());
        let request = Request::new(Method::POST, self.token.clone())
            .idempotent()
            .anonymous()
            .form(&[("grant_type", GRANT_TYPE), ("assertion", jwt.as_str())])
            .keep_status(400);
        drop(jwt);
        let response = self.http.send(&request).await?;
        if response.status() == 400 {
            return Err(Error::Auth {
                detail: self.http.body_detail(&response),
            });
        }
        if !response.is_success() {
            return Err(self.http.reject(&response));
        }
        let issued: Issued =
            response.json("the token endpoint's answer is not in the expected form")?;
        let token = issued
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or(Error::Protocol {
                detail: Detail::constant("the token endpoint answered without an access_token"),
            })?;
        let lifetime = issued.expires_in.map(Duration::from_secs);
        Ok(Token::new(SecretString::from(token), lifetime))
    }

    /// Exchanges a new JWT for a new token, even when a valid one is cached: proves that the key
    /// is accepted now. The new token replaces the cached one.
    pub(super) async fn authenticate(&self) -> Result<(), Error> {
        self.tokens.renew(|| self.fetch()).await?;
        Ok(())
    }

    /// Sends `request` with the access token as a bearer token.
    // Source: Service account flow ("Authorization: Bearer"); lego and dns-update send it so.
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        self.http
            .send_with_token(request, &self.tokens, &TokenAuth::BEARER, || self.fetch())
            .await
    }

    /// The managed zones of the project, all pages; with `dns_name`, only those of that DNS name
    /// (with the trailing dot). A listing is complete or it fails.
    // Source: Discovery document, `managedZones.list` (`dnsName`: "Restricts the list to return
    // only zones with this domain name"; `pageToken`). `maxResults` is not sent: "If
    // unspecified, the server decides how many results to return", and no maximum is
    // documented.
    pub(super) async fn managed_zones(
        &self,
        dns_name: Option<&str>,
    ) -> Result<Vec<ManagedZone>, Error> {
        pager::collect(None::<String>, |token| async move {
            let mut url = self.project_url().path("/managedZones");
            if let Some(dns_name) = dns_name {
                url = url.query("dnsName", dns_name);
            }
            if let Some(token) = &token {
                url = url.query("pageToken", token);
            }
            let response = self.send(&Request::get(url.build()?)).await?;
            if !response.is_success() {
                return Err(self.refusal(&response));
            }
            let page: ZonePage =
                response.json("the provider's managed zone listing is not in the expected form")?;
            Ok(Page {
                items: page.managed_zones,
                next: pager::next_token(page.next_page_token).map(Some),
            })
        })
        .await
    }

    /// The managed zone `zone` (a name or an ID), or `None` for a `404`.
    // Source: Discovery document, `managedZones.get`; AIP-193 (`NOT_FOUND` is 404). Assumption
    // (not observed against the live API): a managed zone that does not exist is answered 404.
    pub(super) async fn managed_zone(&self, zone: &str) -> Result<Option<ManagedZone>, Error> {
        let url = self.project_url().path("/managedZones").id(zone).build()?;
        let response = self.send(&Request::get(url)).await?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response
            .json("the provider's managed zone is not in the expected form")
            .map(Some)
    }

    /// The rrsets of managed zone `zone`, all pages, as the JSON objects the API returned:
    /// every rrset of the zone, or with `filter` those of one name (with the trailing dot) and
    /// type. `None` for a `404`: the zone is not known under this identifier. A listing is
    /// complete or it fails.
    // Source: Discovery document, `resourceRecordSets.list` (`name`: "Specify a fully qualified
    // domain name to view only those records"; `type`: "You must also specify the `name`
    // parameter"; `pageToken`); lego googlecloud.go:402 reads one name and type this way.
    // `maxResults` is not sent (no documented maximum). Assumption (AIP-193, not observed
    // against the live API): a managed zone that does not exist is answered 404; with the name
    // and type filter, a missing rrset is an empty list, so a 404 never means "no rrset".
    pub(super) async fn rrsets(
        &self,
        zone: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<Option<Vec<Value>>, Error> {
        let missing = std::sync::atomic::AtomicBool::new(false);
        let sets = pager::collect(None::<String>, |token| {
            let missing = &missing;
            async move {
                let mut url = self
                    .project_url()
                    .path("/managedZones")
                    .id(zone)
                    .path("/rrsets");
                if let Some((name, rtype)) = filter {
                    url = url.query("name", name).query("type", rtype);
                }
                if let Some(token) = &token {
                    url = url.query("pageToken", token);
                }
                let response = self.send(&Request::get(url.build()?)).await?;
                if response.status() == 404 {
                    missing.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Ok(Page {
                        items: Vec::new(),
                        next: None,
                    });
                }
                if !response.is_success() {
                    return Err(self.refusal(&response));
                }
                let page: RrsetPage =
                    response.json("the provider's rrset listing is not in the expected form")?;
                Ok(Page {
                    items: page.rrsets,
                    next: pager::next_token(page.next_page_token).map(Some),
                })
            }
        })
        .await?;
        if missing.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(None);
        }
        Ok(Some(sets))
    }

    /// The change: deletes `deletions`, each of which must match the stored rrset exactly, and
    /// adds `additions`, atomically; and waits until the change is `done`. Sent once: a repeat
    /// after an unknown outcome would be refused by the exact match or, worse, apply against a
    /// state read before another writer's change (design section 5.3). The caller's repeat of
    /// the operation starts with a read.
    // Source: Changes (atomic; `deletions` "Must match existing data exactly"); Discovery
    // document, `changes.create` ("Atomically updates the ResourceRecordSet collection"). lego
    // sends the deletion and the addition as two separate changes (googlecloud.go:194-255), which
    // leaves a window without the rrset and loses a value written in between; the client does
    // not.
    pub(super) async fn change(
        &self,
        zone: &str,
        deletions: &[Value],
        additions: &[Value],
    ) -> Result<Written, Error> {
        let url = self
            .project_url()
            .path("/managedZones")
            .id(zone)
            .path("/changes")
            .build()?;
        let request = Request::new(Method::POST, url).json(&NewChange {
            additions,
            deletions,
        })?;
        let response = self.send(&request).await?;
        if !response.is_success() {
            // lego treats a 404 answer to a change as a success (googlecloud.go:264-268, without
            // a reason given); the client does not: a 404 can be a zone that went away.
            return Ok(Written::Refused {
                error: self.refusal(&response),
                not_found: response.status() == 404,
            });
        }
        // Accepted: from here on an answer that cannot be read leaves the outcome unknown, and
        // the change may have been applied (design section 3.7).
        let change: Change = response
            .json("the provider's change is not in the expected form")
            .map_err(|_| accepted_unreadable())?;
        self.finish(zone, change).await
    }

    /// Waits until `change` is `done` (design section 3.7). A change still pending after the
    /// last look, a look that fails, or a status the client does not know is `Error::Transient`.
    // Source: Discovery document, `changes.get`; lego googlecloud.go:275-303 polls `Changes.Get`
    // until the status is `done`.
    async fn finish(&self, zone: &str, change: Change) -> Result<Written, Error> {
        match change.status.as_deref() {
            Some(DONE) => return Ok(Written::Done),
            Some(PENDING) => {}
            _ => return Err(accepted_unreadable()),
        }
        let id = change
            .id
            .as_deref()
            .and_then(|id| path_id(id).ok())
            .ok_or_else(accepted_unreadable)?
            .to_owned();
        self.poller
            .run(|| {
                let id = id.clone();
                async move {
                    let change = self.get_change(zone, &id).await?;
                    Ok(match change.status.as_deref() {
                        Some(DONE) => PollStep::Done(Written::Done),
                        Some(PENDING) => PollStep::Pending,
                        _ => PollStep::Failed(accepted_unreadable()),
                    })
                }
            })
            .await
    }

    /// One look at change `id` of managed zone `zone`.
    // Source: Discovery document, `changes.get`.
    async fn get_change(&self, zone: &str, id: &str) -> Result<Change, Error> {
        let url = self
            .project_url()
            .path("/managedZones")
            .id(zone)
            .path("/changes")
            .id(id)
            .build()?;
        let response = self.send(&Request::get(url)).await?;
        if !response.is_success() {
            return Err(self.refusal(&response));
        }
        response.json("the provider's change is not in the expected form")
    }

    /// `{dns_url}/projects/{project}`; the project is percent-encoded as one path segment.
    fn project_url(&self) -> crate::http::url::UrlBuilder {
        self.dns.url().path("/projects").segment(&self.project)
    }

    /// An answer the client does not expect. 401, 403, 429, 413 and 5xx were mapped by the
    /// transport already. A 4xx is a refusal (`Rejected`) with the provider's message and reason;
    /// anything else is an answer the client cannot interpret.
    // Source: AIP-193 (4xx statuses of the `google.rpc.Code` mapping: 400, 404, 409, 412 among
    // them); Error messages (reasons without statuses).
    fn refusal(&self, response: &Response) -> Error {
        match response.status() {
            400..=499 => self.http.reject(response),
            status => Error::Protocol {
                detail: self.http.detail(&format!(
                    "status {status}: {}",
                    self.http.body_detail(response)
                )),
            },
        }
    }
}

/// A change the provider accepted whose answer or status cannot be read: its outcome is unknown,
/// so the error is `Transient`, never `Protocol` (design section 3.7).
fn accepted_unreadable() -> Error {
    Error::Transient {
        detail: Detail::constant(
            "the provider accepted the change, but its status could not be read; the change may \
             have been applied",
        ),
    }
}

/// The documented answer to an exceeded quota besides `429`: `413` (design section 5.3 treats
/// both alike).
// Source: Quotas ("If you exceed a quota, ... an API request returns HTTP 413"); AIP-193
// (`RESOURCE_EXHAUSTED`, 429). The two pages disagree; both statuses are rate limits here.
pub(super) fn rate_limited(response: &Response) -> bool {
    response.status() == 413
}

/// The provider's error message: `error.message` of the API's error body, else the token
/// endpoint's `error_description`, else its `error` code.
// Source: AIP-193 (`error.message`); Service account flow (`error`, `error_description`).
pub(super) fn error_message(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let error = value.get("error");
    error
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .or_else(|| value.get("error_description").and_then(Value::as_str))
        .or_else(|| error.and_then(Value::as_str))
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
}

/// The provider's error code: the `reason` of the first entry of `error.errors`, which the
/// error messages page lists as the codes of Cloud DNS (`alreadyExists`, `preconditionFailed`,
/// ...).
// Source: Error messages (the reasons); google-api-go-client `googleapi.go` (`Error.Errors[]`,
// `ErrorItem.Reason`), the client library lego uses.
pub(super) fn error_code(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    value
        .get("error")?
        .get("errors")?
        .get(0)?
        .get("reason")?
        .as_str()
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{ManagedZone, error_code, error_message};

    #[test]
    fn error_codes_are_the_reason() {
        let body = r#"{"error":{"code":412,"message":"m","status":"FAILED_PRECONDITION","errors":[{"domain":"global","reason":"preconditionFailed","message":"m"}]}}"#;
        assert_eq!(error_code(body).as_deref(), Some("preconditionFailed"));
        assert_eq!(error_code(r#"{"error":{"code":400,"message":"m"}}"#), None);
        assert_eq!(error_code(r#"{"error":"invalid_grant"}"#), None);
        assert_eq!(error_code("<html>oops</html>"), None);
    }

    #[test]
    fn error_messages_are_read_from_either_shape() {
        for (body, expected) in [
            (
                r#"{"error":{"code":404,"message":"The managed zone was not found."}}"#,
                Some("The managed zone was not found."),
            ),
            (
                r#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#,
                Some("Invalid JWT Signature."),
            ),
            (r#"{"error":"invalid_scope"}"#, Some("invalid_scope")),
            (r#"{"error":{"code":400,"message":""}}"#, None),
            ("<html>oops</html>", None),
        ] {
            assert_eq!(error_message(body).as_deref(), expected, "{body}");
        }
    }

    #[test]
    fn zones_are_usable_when_public_and_authoritative() {
        let zone = |json: &str| serde_json::from_str::<ManagedZone>(json).unwrap();
        assert!(zone(r#"{"id":"1","visibility":"public"}"#).usable());
        assert!(zone(r#"{"id":"1"}"#).usable());
        assert!(!zone(r#"{"id":"1","visibility":"private"}"#).usable());
        assert!(!zone(r#"{"id":"1","privateVisibilityConfig":{}}"#).usable());
        assert!(!zone(r#"{"id":"1","visibility":"public","forwardingConfig":{}}"#).usable());
        assert!(!zone(r#"{"id":"1","visibility":"public","peeringConfig":{}}"#).usable());
        assert_eq!(
            zone(r#"{"id":"123","name":"zone-a"}"#).address().unwrap(),
            "123"
        );
        assert_eq!(zone(r#"{"name":"zone-a"}"#).address().unwrap(), "zone-a");
        assert!(zone(r#"{"name":"../x"}"#).address().is_err());
        assert!(zone("{}").address().is_err());
    }

    /// The number of looks at a pending change is bounded: a change that stays pending ends the
    /// write with `Transient` after the last look, and the change is not sent again. The bound
    /// of the client is `MAX_POLLS`; the test lowers it so that it does not wait 120 looks at
    /// the 250 ms floor.
    #[tokio::test]
    async fn a_change_that_stays_pending_is_transient_after_the_last_look() {
        use std::time::Duration;

        use zonewright_mock::google_cloud::{GoogleCloudMock, Seed, test_key};

        use crate::context::{Context, ContextOptions};
        use crate::error::ErrorKind;
        use crate::http::Poller;
        use crate::name::DomainName;
        use crate::provider::Provider as _;
        use crate::providers::google_cloud::{GoogleCloud, GoogleCloudConfig};
        use crate::record::Txt;

        let ctx = Context::new(ContextOptions {
            loopback_only: true,
            ..ContextOptions::default()
        })
        .unwrap();
        let mock = GoogleCloudMock::start(Seed::standard()).await;
        mock.control().set_change_polls(u32::MAX);
        let mut config = GoogleCloudConfig::new("zw-test-project".into());
        config.dns_url = mock.dns_url();
        config.token_url = mock.token_url();
        config.change_poll_ms = 250;
        let key = Seed::standard().key_file(&test_key().private_pem);
        let credentials =
            serde_json::from_value(serde_json::json!({ "service_account_key": key })).unwrap();
        let mut client = GoogleCloud::new(config, credentials, &ctx).unwrap();
        assert_eq!(super::MAX_POLLS, 120);
        client.api.poller = Poller::new(Duration::from_millis(250), 3);
        let zone = DomainName::parse("example.org").unwrap();
        let name = DomainName::parse("_acme-challenge.example.org").unwrap();
        let e = client
            .add_txt_value(&zone, &name, &Txt::new("v1").unwrap(), None)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Transient, "{e:?}");
        let changes = "/dns/v1/projects/*/managedZones/*/changes";
        assert_eq!(mock.log().count(Some("GET"), &format!("{changes}/*")), 3);
        assert_eq!(mock.log().count(Some("POST"), changes), 1);
    }
}
