//! The OpenStack Identity v3 password exchange with project scope, shared by Selectel v2 and VK
//! Cloud (design section 5.7).
//!
//! Reference: OpenStack Identity API v3, "Password authentication with scoped authorization"
//! (<https://docs.openstack.org/api-ref/identity/v3/#password-authentication-with-scoped-authorization>):
//! `POST /v3/auth/tokens` with the user's name, domain and password and a project scope; the
//! token is returned in the `X-Subject-Token` header of a `201 Created` answer, its expiry in the
//! body's `token.expires_at` (ISO 8601) and the project it is scoped to in `token.project.id`.
//! The earlier implementations of both clients accepted `200` as well, and answered `400` with an
//! authentication error; both are kept.
//!
//! The project is named by its ID, or by its name within a domain (a project name is unique only
//! within its domain). Selectel documents both forms of the scope
//! (<https://docs.selectel.ru/api/authorization/>: `"scope": {"project": {"name": ...,
//! "domain": {"name": <account number>}}}`, or `{"project": {"id": ...}}`); the OpenStack
//! reference above defines both.

use bytes::Bytes;
use reqwest::Method;
use reqwest::Url;
use reqwest::header::HeaderName;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::redact::Detail;

use super::Http;
use super::encode;
use super::request::{Request, TokenAuth};
use super::token::{Token, lifetime_until};
use super::url::Endpoint;

/// The header in which Keystone returns the token and in which the APIs behind it expect it.
const X_SUBJECT_TOKEN: &str = "x-subject-token";

/// How the token is sent to the APIs behind Keystone: `X-Auth-Token: <token>`.
pub(crate) const X_AUTH_TOKEN: TokenAuth =
    TokenAuth::new(HeaderName::from_static("x-auth-token"), "");

/// A Keystone password exchange: the token URL and the request body, built once.
///
/// The body carries the password; it lives in a zeroizing buffer for the life of the client
/// and every exchange sends that same buffer. `Debug` shows the URL path only.
pub(crate) struct Keystone {
    url: Url,
    body: Bytes,
}

impl std::fmt::Debug for Keystone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keystone")
            .field("path", &self.url.path())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct AuthRequest<'a> {
    auth: Auth<'a>,
}

#[derive(Serialize)]
struct Auth<'a> {
    identity: Identity<'a>,
    scope: Scope<'a>,
}

#[derive(Serialize)]
struct Identity<'a> {
    methods: [&'static str; 1],
    password: PasswordMethod<'a>,
}

#[derive(Serialize)]
struct PasswordMethod<'a> {
    user: User<'a>,
}

#[derive(Serialize)]
struct User<'a> {
    name: &'a str,
    domain: Named<'a>,
    password: &'a str,
}

#[derive(Serialize)]
struct Named<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct Scope<'a> {
    project: ProjectRef<'a>,
}

/// The `project` member of the scope: `{"id": ..}` or `{"name": .., "domain": {"name": ..}}`.
#[derive(Serialize)]
#[serde(untagged)]
enum ProjectRef<'a> {
    Id { id: &'a str },
    Name { name: &'a str, domain: Named<'a> },
}

/// The project a token is scoped to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectScope<'a> {
    /// The project with this ID.
    Id(&'a str),
    /// The project with this name in the Keystone domain `domain`.
    Name {
        /// The project's name.
        name: &'a str,
        /// The domain the project belongs to.
        domain: &'a str,
    },
}

/// What an exchange returns: the token, and the ID of the project it is scoped to when the
/// answer states one (which a client scoped by project name needs to recognize its project).
pub(crate) struct Issued {
    /// The token and its lifetime.
    pub(crate) token: Token,
    /// `token.project.id` of the answer.
    pub(crate) project_id: Option<String>,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("token", &self.token)
            .field("project_id", &self.project_id)
            .finish()
    }
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: TokenBody,
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    project: Option<ProjectBody>,
}

#[derive(Deserialize)]
struct ProjectBody {
    #[serde(default)]
    id: Option<String>,
}

impl Keystone {
    /// An exchange against the identity endpoint `identity` (the URL that ends in `/v3`) for
    /// user `user_name` in domain `user_domain`, scoped to `project`. The password must also be
    /// registered with the client's scrubber.
    pub(crate) fn new(
        identity: &Endpoint,
        user_name: &str,
        user_domain: &str,
        project: ProjectScope<'_>,
        password: &SecretString,
    ) -> Result<Keystone, Error> {
        use secrecy::ExposeSecret as _;
        let url = identity.url().path("/auth/tokens").build()?;
        let body = encode::json(&AuthRequest {
            auth: Auth {
                identity: Identity {
                    methods: ["password"],
                    password: PasswordMethod {
                        user: User {
                            name: user_name,
                            domain: Named { name: user_domain },
                            password: password.expose_secret(),
                        },
                    },
                },
                scope: Scope {
                    project: match project {
                        ProjectScope::Id(id) => ProjectRef::Id { id },
                        ProjectScope::Name { name, domain } => ProjectRef::Name {
                            name,
                            domain: Named { name: domain },
                        },
                    },
                },
            },
        })?;
        Ok(Keystone { url, body })
    }

    /// Exchanges the password for a token, for a [`TokenSource`](super::TokenSource) fetch
    /// closure: [`Keystone::fetch`] without the project ID.
    pub(crate) async fn fetch_token(&self, http: &Http) -> Result<Token, Error> {
        self.fetch(http).await.map(|issued| issued.token)
    }

    /// Exchanges the password for a token. The transport registers the token with `http`'s
    /// scrubber when [`Http::send_with_token`] first uses it; until then it appears in no error.
    ///
    /// Answers: 200 or 201 with `X-Subject-Token` is the token, its lifetime from
    /// `token.expires_at` (none stated when absent or unreadable, which the token cache treats
    /// as one hour) and the project from `token.project.id`; 400 and 401 are `Error::Auth`;
    /// 403, 429 and 5xx follow the shared mapping; anything else is `Error::Rejected`.
    pub(crate) async fn fetch(&self, http: &Http) -> Result<Issued, Error> {
        let request = Request::new(Method::POST, self.url.clone())
            .idempotent()
            .anonymous()
            .body(encode::JSON, self.body.clone())
            .keep_status(400);
        let response = http.send(&request).await?;
        match response.status() {
            200 | 201 => {}
            400 => {
                return Err(Error::Auth {
                    detail: http.body_detail(&response),
                });
            }
            _ => return Err(http.reject(&response)),
        }
        let token = response
            .header(X_SUBJECT_TOKEN)
            .filter(|t| !t.is_empty())
            .ok_or(Error::Protocol {
                detail: Detail::constant(
                    "the identity service answered without an X-Subject-Token header",
                ),
            })?;
        let body = response
            .json::<TokenAnswer>("the identity service's token answer is not in the expected form")
            .ok()
            .map(|answer| answer.token);
        let lifetime = body
            .as_ref()
            .and_then(|body| body.expires_at.as_deref())
            .and_then(lifetime_until);
        let project_id = body
            .and_then(|body| body.project)
            .and_then(|project| project.id)
            .filter(|id| !id.is_empty());
        Ok(Issued {
            token: Token::new(SecretString::from(token), lifetime),
            project_id,
        })
    }
}
