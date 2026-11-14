//! AWS Signature Version 4.
//!
//! Algorithm: AWS documentation, "Create a signed AWS API request"
//! (<https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html>).
//!
//! `host`, `x-amz-date` and, with temporary credentials, `x-amz-security-token` are always
//! signed; the caller adds further headers. The caller supplies the payload hash
//! ([`payload_hash`] of the body, or `UNSIGNED-PAYLOAD` where the service allows it) and sets
//! the `x-amz-date`, `x-amz-security-token` and `Authorization` headers itself.
//!
//! Intermediates that contain the secret key or the session token (the `AWS4`-prefixed key, the
//! derived keys, the canonical request, the string to sign) are held in zeroizing buffers sized
//! up front, so that they are not reallocated and leave no unwiped copy behind.

use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::{KeyError, hex_lower, hmac_sha256, push_hex_byte, sha256};

/// The signing algorithm's identifier.
pub(crate) const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Headers the signer sets itself; an extra header may not use these names.
const RESERVED_HEADERS: [&str; 4] = [
    "authorization",
    "host",
    "x-amz-date",
    "x-amz-security-token",
];

/// Access keys. `Debug` shows the access key ID only; the secrets are `SecretString`.
#[derive(Debug)]
pub(crate) struct Keys<'a> {
    /// The access key ID; not a secret.
    pub access_key_id: &'a str,
    /// The secret access key.
    pub secret: &'a SecretString,
    /// The session token of temporary credentials.
    pub session_token: Option<&'a SecretString>,
}

/// The credential scope: region and service.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scope<'a> {
    /// The region, `us-east-1` for a global service.
    pub region: &'a str,
    /// The service, for example `route53`.
    pub service: &'a str,
}

/// A request to sign.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Request<'a> {
    /// The HTTP method in uppercase.
    pub method: &'a str,
    /// `host[:port]` exactly as sent in the `Host` header.
    pub host: &'a str,
    /// The path, already canonical (URI-encoded, normalized).
    pub path: &'a str,
    /// The query string from [`canonical_query`]; the same string is sent in the URL.
    pub query: &'a str,
    /// Extra signed headers with lowercase names, other than `host`, `x-amz-date`,
    /// `x-amz-security-token` and `authorization`.
    pub headers: &'a [(&'a str, &'a str)],
    /// Lowercase hex SHA-256 of the body, or `UNSIGNED-PAYLOAD`.
    pub payload_hash: &'a str,
}

/// Appends `s` URI-encoded as SigV4 requires: `A-Z a-z 0-9 - _ . ~` as they are, every other
/// byte as `%XX` with uppercase hex.
fn uri_encode(s: &str, out: &mut String) {
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            push_hex_byte(out, b, true);
        }
    }
}

/// The canonical query string: names and values URI-encoded, pairs sorted by name and then by
/// value, joined by `&`. The same string goes into the URL, so what is signed is what is sent.
pub(crate) fn canonical_query(pairs: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(name, value)| {
            let mut n = String::with_capacity(name.len());
            let mut v = String::with_capacity(value.len());
            uri_encode(name, &mut n);
            uri_encode(value, &mut v);
            (n, v)
        })
        .collect();
    encoded.sort();
    let mut out = String::new();
    for (i, (name, value)) in encoded.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    out
}

/// Lowercase hex SHA-256 of the body.
pub(crate) fn payload_hash(body: &[u8]) -> String {
    hex_lower(&sha256(body))
}

/// `amz_date` is "YYYYMMDDTHHMMSSZ". Returns the Authorization header value.
///
/// Errors: [`KeyError::Date`] for a malformed date, [`KeyError::Request`] for a request part
/// that cannot be signed as given (see [`KeyError`]). Neither carries input.
pub(crate) fn authorization(
    request: &Request<'_>,
    keys: &Keys<'_>,
    scope: Scope<'_>,
    amz_date: &str,
) -> Result<Zeroizing<String>, KeyError> {
    let date = date_part(amz_date)?;
    check_scope(scope)?;
    if !is_token(keys.access_key_id) {
        return Err(KeyError::Request);
    }
    let token = keys.session_token.map(|t| t.expose_secret());
    let (creq, signed_headers) = canonical_request(request, amz_date, token)?;
    let credential_scope = credential_scope(date, scope);
    let string_to_sign = string_to_sign(&creq, amz_date, &credential_scope);

    let secret = keys.secret.expose_secret();
    let mut k_secret = Zeroizing::new(String::with_capacity(4 + secret.len()));
    k_secret.push_str("AWS4");
    k_secret.push_str(secret);
    let k_date = Zeroizing::new(hmac_sha256(k_secret.as_bytes(), date.as_bytes()));
    let k_region = Zeroizing::new(hmac_sha256(k_date.as_ref(), scope.region.as_bytes()));
    let k_service = Zeroizing::new(hmac_sha256(k_region.as_ref(), scope.service.as_bytes()));
    let k_signing = Zeroizing::new(hmac_sha256(k_service.as_ref(), b"aws4_request"));
    let signature = hex_lower(&hmac_sha256(k_signing.as_ref(), string_to_sign.as_bytes()));

    let parts = [
        ALGORITHM,
        " Credential=",
        keys.access_key_id,
        "/",
        credential_scope.as_str(),
        ", SignedHeaders=",
        signed_headers.as_str(),
        ", Signature=",
        signature.as_str(),
    ];
    let mut header = Zeroizing::new(String::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for part in parts {
        header.push_str(part);
    }
    Ok(header)
}

/// The `YYYYMMDD` part of a well-formed `amz_date`, taken with checked slicing.
fn date_part(amz_date: &str) -> Result<&str, KeyError> {
    let well_formed = amz_date.len() == 16
        && amz_date.bytes().enumerate().all(|(i, b)| match i {
            8 => b == b'T',
            15 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    if !well_formed {
        return Err(KeyError::Date);
    }
    amz_date.get(..8).ok_or(KeyError::Date)
}

/// `date/region/service/aws4_request`.
fn credential_scope(date: &str, scope: Scope<'_>) -> String {
    let parts = [date, "/", scope.region, "/", scope.service, "/aws4_request"];
    let mut out = String::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.push_str(part);
    }
    out
}

/// True for a non-empty string of visible ASCII without `/` or a space, the form of a region,
/// a service and an access key ID.
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
}

fn check_scope(scope: Scope<'_>) -> Result<(), KeyError> {
    if is_token(scope.region) && is_token(scope.service) {
        Ok(())
    } else {
        Err(KeyError::Request)
    }
}

/// True for a header name the signer accepts: lowercase letters, digits and `-`.
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// True for text without control characters, the form of a header value.
fn is_header_value(value: &str) -> bool {
    !value.chars().any(char::is_control)
}

/// True for a part of the request line: non-empty visible ASCII.
fn is_request_part(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Checks the request and returns its headers, the always-signed ones included, sorted by name.
fn signed_header_list<'a>(
    request: &Request<'a>,
    amz_date: &'a str,
    token: Option<&'a str>,
) -> Result<Vec<(&'a str, &'a str)>, KeyError> {
    let method_ok =
        !request.method.is_empty() && request.method.bytes().all(|b| b.is_ascii_uppercase());
    let query_ok = request.query.bytes().all(|b| b.is_ascii_graphic());
    if !method_ok
        || !is_request_part(request.host)
        || !is_request_part(request.path)
        || !request.path.starts_with('/')
        || !query_ok
        || !is_request_part(request.payload_hash)
    {
        return Err(KeyError::Request);
    }
    let mut headers: Vec<(&str, &str)> = Vec::with_capacity(3 + request.headers.len());
    headers.push(("host", request.host));
    headers.push(("x-amz-date", amz_date));
    if let Some(token) = token {
        // An empty token would be signed as an empty header the client then has to send; that
        // is a caller's mistake, not a request to sign.
        if token.is_empty() || !is_header_value(token) {
            return Err(KeyError::Request);
        }
        headers.push(("x-amz-security-token", token));
    }
    for &(name, value) in request.headers {
        if !is_header_name(name) || RESERVED_HEADERS.contains(&name) || !is_header_value(value) {
            return Err(KeyError::Request);
        }
        headers.push((name, value));
    }
    headers.sort_by(|a, b| a.0.cmp(b.0));
    if headers
        .windows(2)
        .any(|pair| matches!(pair, [a, b] if a.0 == b.0))
    {
        return Err(KeyError::Request);
    }
    Ok(headers)
}

/// Appends a header value in canonical form: leading and trailing spaces and tabs removed, runs
/// of spaces inside collapsed to one. Writes into `out` directly, so a secret value is never
/// copied into a buffer of its own.
fn push_canonical_value(out: &mut String, value: &str) {
    let mut previous_space = false;
    for c in value.trim_matches([' ', '\t']).chars() {
        if c == ' ' {
            if !previous_space {
                out.push(' ');
            }
            previous_space = true;
        } else {
            out.push(c);
            previous_space = false;
        }
    }
}

/// The canonical request and the signed-header list. With a session token the canonical
/// request contains it in clear, so it is built in a zeroizing buffer sized up front.
fn canonical_request(
    request: &Request<'_>,
    amz_date: &str,
    token: Option<&str>,
) -> Result<(Zeroizing<String>, String), KeyError> {
    let headers = signed_header_list(request, amz_date, token)?;
    let mut signed = String::with_capacity(headers.iter().map(|(name, _)| name.len() + 1).sum());
    for (i, (name, _)) in headers.iter().enumerate() {
        if i > 0 {
            signed.push(';');
        }
        signed.push_str(name);
    }
    // method, path, query, each header line, the empty line, the signed list, the payload hash,
    // and one newline after each of the first six parts. Canonical values are never longer than
    // the given ones.
    let capacity = request.method.len()
        + request.path.len()
        + request.query.len()
        + headers
            .iter()
            .map(|(name, value)| name.len() + value.len() + 2)
            .sum::<usize>()
        + signed.len()
        + request.payload_hash.len()
        + 6;
    let mut creq = Zeroizing::new(String::with_capacity(capacity));
    for part in [
        request.method,
        "\n",
        request.path,
        "\n",
        request.query,
        "\n",
    ] {
        creq.push_str(part);
    }
    for (name, value) in &headers {
        creq.push_str(name);
        creq.push(':');
        push_canonical_value(&mut creq, value);
        creq.push('\n');
    }
    for part in ["\n", signed.as_str(), "\n", request.payload_hash] {
        creq.push_str(part);
    }
    Ok((creq, signed))
}

/// `ALGORITHM \n amz_date \n credential_scope \n hex(SHA-256(canonical request))`.
fn string_to_sign(creq: &str, amz_date: &str, credential_scope: &str) -> Zeroizing<String> {
    let hash = hex_lower(&sha256(creq.as_bytes()));
    let parts = [
        ALGORITHM,
        "\n",
        amz_date,
        "\n",
        credential_scope,
        "\n",
        hash.as_str(),
    ];
    let mut out = Zeroizing::new(String::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for part in parts {
        out.push_str(part);
    }
    out
}

#[cfg(test)]
mod tests {
    //! Known answers from the AWS Signature Version 4 test suite as maintained in the AWS
    //! Common Runtime, `awslabs/aws-c-auth`, `tests/aws-signing-test-suite/v4/<case>/` (tag
    //! v0.9.0), in the copy distributed with the `aws-sigv4` crate 1.6.0. Each test is named
    //! after its case and compares with the case's `header-canonical-request.txt`,
    //! `header-string-to-sign.txt` and `header-signed-request.txt` (Authorization line). All
    //! cases share `context.json`: access key `AKIDEXAMPLE`, the suite's example secret key,
    //! region `us-east-1`, service `service`, time 2015-08-30T12:36:00Z.

    use super::*;

    const AKID: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const DATE: &str = "20150830T123600Z";
    const SCOPE: Scope<'static> = Scope {
        region: "us-east-1",
        service: "service",
    };
    const CREDENTIAL_SCOPE: &str = "20150830/us-east-1/service/aws4_request";
    const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HOST: &str = "example.amazonaws.com";

    fn request<'a>(
        method: &'a str,
        query: &'a str,
        headers: &'a [(&'a str, &'a str)],
        payload_hash: &'a str,
    ) -> Request<'a> {
        Request {
            method,
            host: HOST,
            path: "/",
            query,
            headers,
            payload_hash,
        }
    }

    /// Checks the canonical request, the string to sign and the Authorization value.
    fn check(
        request: &Request<'_>,
        token: Option<&str>,
        expected_creq: &str,
        expected_sts: &str,
        expected_authorization: &str,
    ) {
        let (creq, _) = canonical_request(request, DATE, token).unwrap();
        assert_eq!(creq.as_str(), expected_creq);
        let sts = string_to_sign(&creq, DATE, CREDENTIAL_SCOPE);
        assert_eq!(sts.as_str(), expected_sts);
        let secret = SecretString::from(SECRET.to_owned());
        let token = token.map(|t| SecretString::from(t.to_owned()));
        let keys = Keys {
            access_key_id: AKID,
            secret: &secret,
            session_token: token.as_ref(),
        };
        let header = authorization(request, &keys, SCOPE, DATE).unwrap();
        assert_eq!(header.as_str(), expected_authorization);
        assert!(!header.contains(SECRET));
        if let Some(token) = &token {
            assert!(!header.contains(token.expose_secret()));
        }
    }

    #[test]
    fn get_vanilla() {
        check(
            &request("GET", "", &[], EMPTY_HASH),
            None,
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        );
        assert_eq!(payload_hash(b""), EMPTY_HASH);
    }

    #[test]
    fn get_vanilla_query_order_key_case() {
        // request.txt: `GET /?Param2=value2&Param1=value1`.
        let query = canonical_query(&[("Param2", "value2"), ("Param1", "value1")]);
        assert_eq!(query, "Param1=value1&Param2=value2");
        check(
            &request("GET", &query, &[], EMPTY_HASH),
            None,
            "GET\n/\nParam1=value1&Param2=value2\nhost:example.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             816cd5b414d056048ba4f7c5386d6e0533120fb1fcfa93762cf0fc39e2cf19e0",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500",
        );
    }

    #[test]
    fn post_x_www_form_urlencoded() {
        // request.txt: body `Param1=value1`, signed with `x-amz-content-sha256` (sign_body).
        let hash = payload_hash(b"Param1=value1");
        assert_eq!(
            hash,
            "9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e"
        );
        let headers = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "13"),
            ("x-amz-content-sha256", hash.as_str()),
        ];
        check(
            &request("POST", "", &headers, &hash),
            None,
            "POST\n/\n\ncontent-length:13\ncontent-type:application/x-www-form-urlencoded\n\
             host:example.amazonaws.com\n\
             x-amz-content-sha256:9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e\n\
             x-amz-date:20150830T123600Z\n\n\
             content-length;content-type;host;x-amz-content-sha256;x-amz-date\n\
             9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             b1edd1d03544c25390e32085d55b57acc9a3961bb59415ff86c45c3d89d16cfb",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date, \
             Signature=d3875051da38690788ef43de4db0d8f280229d82040bfac253562e56c3f20e0b",
        );
    }

    #[test]
    fn get_vanilla_with_session_token() {
        let token = "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267";
        check(
            &request("GET", "", &[], EMPTY_HASH),
            Some(token),
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\
             x-amz-security-token:6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267\n\n\
             host;x-amz-date;x-amz-security-token\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             067b36aa60031588cea4a4cde1f21215227a047690c72247f1d70b32fbbfad2b",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date;x-amz-security-token, \
             Signature=07ec1639c89043aa0e3e2de82b96708f198cceab042d4a97044c66dd9f74e7f8",
        );
    }

    #[test]
    fn post_sts_header_before() {
        let token = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
        let creq = format!(
            "POST\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\
             x-amz-security-token:{token}\n\nhost;x-amz-date;x-amz-security-token\n{EMPTY_HASH}"
        );
        check(
            &request("POST", "", &[], EMPTY_HASH),
            Some(token),
            &creq,
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             c237e1b440d4c63c32ca95b5b99481081cb7b13c7e40434868e71567c1a882f6",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date;x-amz-security-token, \
             Signature=85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead",
        );
    }

    #[test]
    fn get_header_value_trim() {
        // request.txt: `My-Header1: value1` and `My-Header2: "a   b   c"`.
        let headers = [("my-header1", " value1"), ("my-header2", "\"a   b   c\"")];
        check(
            &request("GET", "", &headers, EMPTY_HASH),
            None,
            "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nmy-header2:\"a b c\"\n\
             x-amz-date:20150830T123600Z\n\nhost;my-header1;my-header2;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n\
             a726db9b0df21c14f559d0a978e563112acb1b9e05476f0a6a1c7d68f28605c7",
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;my-header1;my-header2;x-amz-date, \
             Signature=acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
        );
    }

    #[test]
    fn canonical_buffers_are_zeroizing_and_hold_the_token() {
        let (creq, signed) = canonical_request(
            &request("GET", "", &[], EMPTY_HASH),
            DATE,
            Some("token-canary"),
        )
        .unwrap();
        // The type is the check: the canonical request is wiped on drop.
        let creq: Zeroizing<String> = creq;
        assert!(creq.contains("x-amz-security-token:token-canary\n"));
        assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
        let sts: Zeroizing<String> = string_to_sign(&creq, DATE, CREDENTIAL_SCOPE);
        assert!(!sts.contains("token-canary"));
    }

    #[test]
    fn secret_and_token_do_not_occur_in_output_or_debug() {
        let secret = SecretString::from("secret-canary+/=".to_owned());
        let token = SecretString::from("token-canary+/=".to_owned());
        let keys = Keys {
            access_key_id: AKID,
            secret: &secret,
            session_token: Some(&token),
        };
        let header =
            authorization(&request("GET", "", &[], EMPTY_HASH), &keys, SCOPE, DATE).unwrap();
        let debug = format!("{keys:?}");
        for text in [header.as_str(), debug.as_str()] {
            assert!(
                !text.contains("secret-canary") && !text.contains("token-canary"),
                "{text}"
            );
        }
        assert!(debug.contains(AKID));
    }

    #[test]
    fn malformed_dates_are_errors() {
        let secret = SecretString::from(SECRET.to_owned());
        let keys = Keys {
            access_key_id: AKID,
            secret: &secret,
            session_token: None,
        };
        let req = request("GET", "", &[], EMPTY_HASH);
        for date in [
            "",
            "2015",
            "20150830",
            "20150830T123600",
            "20150830T123600ZZ",
            "20150830 123600Z",
            "2015-08-30T12:36:00Z",
            "2015083\u{20ac}T123600Z",
            "\u{20ac}\u{20ac}\u{20ac}\u{20ac}\u{20ac}T",
            "20150830t123600z",
        ] {
            assert_eq!(
                authorization(&req, &keys, SCOPE, date).unwrap_err(),
                KeyError::Date,
                "{date:?}"
            );
        }
    }

    #[test]
    fn requests_that_cannot_be_signed_are_errors() {
        let secret = SecretString::from(SECRET.to_owned());
        let empty = SecretString::from(String::new());
        let keys = Keys {
            access_key_id: AKID,
            secret: &secret,
            session_token: None,
        };
        let sign = |req: &Request<'_>| authorization(req, &keys, SCOPE, DATE);
        let base = request("GET", "", &[], EMPTY_HASH);
        assert!(sign(&base).is_ok());
        let bad_requests = [
            Request { method: "", ..base },
            Request {
                method: "get",
                ..base
            },
            Request { host: "", ..base },
            Request {
                host: "a b",
                ..base
            },
            Request {
                host: "a\r\nX-Injected: 1",
                ..base
            },
            Request { path: "", ..base },
            Request {
                path: "relative",
                ..base
            },
            Request {
                query: "a=b c",
                ..base
            },
            Request {
                payload_hash: "",
                ..base
            },
            Request {
                headers: &[("Content-Type", "x")],
                ..base
            },
            Request {
                headers: &[("host", "other")],
                ..base
            },
            Request {
                headers: &[("x-amz-date", DATE)],
                ..base
            },
            Request {
                headers: &[("x-amz-security-token", "t")],
                ..base
            },
            Request {
                headers: &[("authorization", "x")],
                ..base
            },
            Request {
                headers: &[("a", "1"), ("a", "2")],
                ..base
            },
            Request {
                headers: &[("a", "line\nbreak")],
                ..base
            },
            Request {
                headers: &[("", "x")],
                ..base
            },
        ];
        for req in &bad_requests {
            assert_eq!(sign(req).unwrap_err(), KeyError::Request, "{req:?}");
        }
        for scope in [
            Scope {
                region: "",
                service: "s",
            },
            Scope {
                region: "us-east-1",
                service: "a/b",
            },
            Scope {
                region: "us east",
                service: "s",
            },
        ] {
            assert_eq!(
                authorization(&base, &keys, scope, DATE).unwrap_err(),
                KeyError::Request
            );
        }
        let with_empty_token = Keys {
            session_token: Some(&empty),
            ..keys
        };
        assert_eq!(
            authorization(&base, &with_empty_token, SCOPE, DATE).unwrap_err(),
            KeyError::Request
        );
        let bad_akid = Keys {
            access_key_id: "AKID/EXAMPLE",
            ..keys
        };
        assert_eq!(
            authorization(&base, &bad_akid, SCOPE, DATE).unwrap_err(),
            KeyError::Request
        );
    }

    #[test]
    fn query_encoding() {
        assert_eq!(
            canonical_query(&[("name", "_acme-challenge.a.example."), ("type", "TXT")]),
            "name=_acme-challenge.a.example.&type=TXT"
        );
        assert_eq!(
            canonical_query(&[("k", "a b/*=~\u{e9}")]),
            "k=a%20b%2F%2A%3D~%C3%A9"
        );
        assert_eq!(
            canonical_query(&[("b", "2"), ("a", "2"), ("a", "1")]),
            "a=1&a=2&b=2"
        );
        assert_eq!(canonical_query(&[("uploads", "")]), "uploads=");
        assert_eq!(canonical_query(&[]), "");
    }
}
