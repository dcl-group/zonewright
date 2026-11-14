//! The acme-dns HTTP API as this client uses it: the one request it has, and the classification
//! of its answers.
//!
//! Sources (hard rule 3):
//!
//! - [README]: <https://github.com/joohoi/acme-dns/blob/master/README.md>, "Update endpoint":
//!   `POST /update` with the headers `X-Api-User` and `X-Api-Key` and the body
//!   `{"subdomain": …, "txt": …}`, answered `200` with `{"txt": …}`.
//! - [server]: the project's source, `pkg/api/` (`api.go`, `auth.go`, `update.go`, `util.go`) and
//!   `pkg/database/db.go`, read on 2026-11-14 at commit `43b0acaacef24d1058d70ed584d6b7275a8344ed`.
//! - lego `providers/dns/acmedns/acmedns.go` (lines 142 and 147-150: Present updates the TXT
//!   value, CleanUp does nothing, "ACME-DNS doesn't support the notion of removing a record") and
//!   its client library `github.com/nrdcg/goacmedns`, `client.go`, `UpdateTXTRecord`.
//!
//! What the server source establishes about `POST /update`:
//!
//! - The `Auth` middleware (`auth.go`) runs first. It answers `401` with `{"error": "forbidden"}`
//!   for every refusal: an invalid user name or key (the key must be 40 characters of the base64url
//!   alphabet, the user name a UUID), a wrong password, a source address outside the
//!   registration's `allowfrom` networks, and a `subdomain` in the body that is not the
//!   registration's. A body that is not JSON leaves the subdomain empty and ends the same way.
//! - Only then the handler (`update.go`) checks the body: a subdomain that fails `validSubdomain`
//!   is `400` `bad_subdomain`, a `txt` that fails `validTXT` is `400` `bad_txt`. `validTXT`
//!   (`util.go`) accepts exactly 43 characters, all of the alphabet `A-Z a-z 0-9 - _`.
//! - A valid update writes the value into the row of the registration with the oldest
//!   `LastUpdate`, without comparing values (`db.go`, `Update`), and answers `200`. A database
//!   failure is `500` `db_error`.
//!
//! The README documents the request, the headers and the `200` answer. The status codes and the
//! error texts above are from the source; the README names none of them. The order of the checks
//! is the same in every release from v0.1 to v2.0.2 and on `master`, with one difference: up to
//! v0.3.2 an invalid `txt` is answered `400` `bad_subdomain`. The client never relies on either
//! code: it sends only values that pass `validTXT`, and treats any other answer as a refusal.
//!
//! The API has no other call this client needs: `POST /register` creates registrations (the
//! application does that, once, and passes the answer as the credentials) and `GET /health` is a
//! liveness probe.

use reqwest::Method;
use reqwest::header::HeaderName;
use secrecy::ExposeSecret as _;
use serde::Serialize;

use crate::error::Error;
use crate::http::{Endpoint, Http, Request};

use super::config::Registration;

/// The user name header.
// Source: README, "Update endpoint", required headers.
const USER_HEADER: HeaderName = HeaderName::from_static("x-api-user");

/// The key header.
// Source: README, "Update endpoint", required headers.
const KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

/// The body of `POST /update`.
// Source: README, "Update endpoint", example input.
#[derive(Serialize)]
struct UpdateBody<'a> {
    /// The registration's subdomain.
    subdomain: &'a str,
    /// The value.
    txt: &'a str,
}

/// The API of one acme-dns server.
pub(super) struct Api {
    http: Http,
    endpoint: Endpoint,
}

impl Api {
    pub(super) fn new(http: Http, endpoint: Endpoint) -> Api {
        Api { http, endpoint }
    }

    /// The server URL as the client spells it, which keys the client's memory.
    pub(super) fn server(&self) -> &str {
        self.endpoint.as_url().as_str()
    }

    /// Sends `POST /update` once, whatever happens: it is a write, and a repeat of one that
    /// reached the server could displace a live value (design sections 5.3 and 11.3).
    async fn update(
        &self,
        registration: &Registration,
        txt: &str,
    ) -> Result<crate::http::Response, Error> {
        let url = self.endpoint.url().path("/update").build()?;
        let body = UpdateBody {
            subdomain: &registration.subdomain,
            txt,
        };
        let request = Request::new(Method::POST, url)
            .secret_header(USER_HEADER, "", registration.username.expose_secret())?
            .secret_header(KEY_HEADER, "", registration.password.expose_secret())?
            .json(&body)?;
        self.http.send(&request).await
    }

    /// Stores `value` in the registration. Any 2xx answer is success; the body is not needed.
    pub(super) async fn store(
        &self,
        registration: &Registration,
        value: &str,
    ) -> Result<(), Error> {
        let response = self.update(registration, value).await?;
        if response.is_success() {
            Ok(())
        } else {
            Err(self.http.reject(&response))
        }
    }
}
