//! Bearer-token authentication and role-based access control, plus the
//! rate-limit key extractor that decides what counts as "one client" for
//! `tower_governor`.
//!
//! The router that wires these handlers together lives in [`super`].

use super::*;
use axum::http::HeaderMap;
use axum::http::header::FORWARDED;
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use tower_governor::errors::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

/// Roles injected into every authenticated request via the `require_auth` middleware.
/// The SHA-256 of the token a request came with, for binding state to the
/// caller that created it. Inserted beside [`Role`] by `require_auth`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller(pub String);

/// Handlers that perform write or administrative operations extract this to enforce
/// per-route privilege requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full administrative access: create/delete tokens, manage webhooks, edit
    /// policies and config, approve agent actions.
    Admin,
    /// Read-only observer: may call all GET endpoints and the SSE stream.
    Auditor,
    /// Programmatic agent identity: may create sessions and submit approvals.
    Agent,
}

impl Role {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "auditor" => Some(Role::Auditor),
            "agent" => Some(Role::Agent),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Auditor => "auditor",
            Role::Agent => "agent",
        }
    }
}

/// Routes that take `?token=`: a browser cannot set headers on an
/// `EventSource` or a plain link. Elsewhere a token in the URL is refused,
/// since URLs end up in logs, history and `Referer` headers.
fn accepts_query_token(path: &str) -> bool {
    path == "/api/stream"
        || path == "/metrics"
        || path
            .strip_prefix("/api/sessions/")
            .and_then(|rest| rest.strip_suffix("/events/stream"))
            .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

pub(crate) async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let (parts, body) = request.into_parts();

    let bearer = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let query_token = parts.uri.query().and_then(|q| {
        // Use proper form-urlencoded parsing so tokens that contain `+` or
        // `%xx` sequences are correctly decoded before the SHA-256 comparison.
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "token")
            .map(|(_, v)| v.into_owned())
    });
    let token = match (bearer, query_token) {
        (Some(token), _) => token,
        (None, Some(token)) if accepts_query_token(parts.uri.path()) => token,
        (None, Some(_)) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Send the token in the Authorization header; ?token= is accepted only on \
                 /api/stream, session event streams and /metrics"
                    .into(),
            ));
        }
        (None, None) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                "Missing authentication token".into(),
            ));
        }
    };

    // Hash the raw token before the DB lookup so the raw credential is never
    // compared or stored beyond this function's stack frame.
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

    let row = state.pool.find_token_role(&token_hash).await.map_err(|e| {
        tracing::error!("Token lookup failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Token lookup failed: {e}"),
        )
    })?;

    let role = match row {
        Some(ref s) => Role::from_str(s)
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, format!("Unknown role: {s}")))?,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid or expired token".into())),
    };

    // Inject the resolved role into request extensions so individual handlers can
    // enforce their own minimum privilege requirements without splitting the router.
    let mut req = Request::from_parts(parts, body);
    req.extensions_mut().insert(role);
    req.extensions_mut().insert(Caller(token_hash));
    Ok(next.run(req).await)
}

/// Rate-limit key extractor: keys on the socket peer address, and only
/// substitutes a client IP taken from `X-Forwarded-For` / `X-Real-Ip` /
/// `Forwarded` when the peer itself is a configured trusted proxy.
///
/// `tower_governor`'s `SmartIpKeyExtractor` trusts those headers
/// unconditionally, which lets any direct caller put a fresh IP in
/// `X-Forwarded-For` on every request and evade its own rate limit. Behind a
/// real reverse proxy, only the proxy's address ever appears as the peer, so
/// trusting the header only from that address keeps the legitimate case
/// working while closing the spoof.
#[derive(Clone)]
pub(crate) struct TrustedProxyKeyExtractor {
    trusted: std::sync::Arc<Vec<IpNetwork>>,
}

impl TrustedProxyKeyExtractor {
    /// Builds the extractor from already-parsed trusted-proxy networks, so
    /// callers (production wiring, or a test harness that wants a specific
    /// list without touching process-global env vars) share one parser.
    pub(crate) fn new(trusted: Vec<IpNetwork>) -> Self {
        Self {
            trusted: std::sync::Arc::new(trusted),
        }
    }
}

/// Parses `ECTO_TRUSTED_PROXIES` entries (from [`config::trusted_proxies`])
/// into networks, logging and skipping anything that isn't a valid IP or
/// CIDR rather than failing startup over an operator typo.
pub(crate) fn parse_trusted_proxies(raw: &[String]) -> Vec<IpNetwork> {
    raw.iter()
        .filter_map(|entry| match entry.parse::<IpNetwork>() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(
                    "ECTO_TRUSTED_PROXIES entry '{entry}' is not a valid IP/CIDR ({e}); ignored"
                );
                None
            }
        })
        .collect()
}

fn is_trusted_peer(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    let ip = ip.to_canonical();
    trusted.iter().any(|net| net.contains(ip))
}

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_REAL_IP: &str = "x-real-ip";

/// Reads the client IP a trusted proxy reported, trying `X-Forwarded-For`,
/// then `X-Real-Ip`, then `Forwarded`, in that order.
///
/// `X-Forwarded-For` can carry a chain a client partially forged before it
/// ever reached the (one, directly-connected) trusted proxy: each hop
/// *appends* the address it saw as its peer, so a value the client set
/// itself sits to the left of what the trusted proxy actually observed.
/// Walking right-to-left and taking the first entry that is not itself a
/// trusted proxy recovers that observed address and skips the forged one.
fn forwarded_header_ip(headers: &HeaderMap, trusted: &[IpNetwork]) -> Option<IpAddr> {
    let mut xff = Vec::new();
    for value in headers.get_all(X_FORWARDED_FOR).iter() {
        xff.extend(value.to_str().ok()?.split(','));
    }
    for part in xff.into_iter().rev() {
        // An unknown hop breaks the trust chain; never skip it and trust a
        // client-controlled address farther to the left.
        let ip = part.trim().parse::<IpAddr>().ok()?.to_canonical();
        if !is_trusted_peer(ip, trusted) {
            return Some(ip);
        }
    }
    if let Some(ip) = headers
        .get(X_REAL_IP)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ip);
    }
    let mut chain = Vec::new();
    for value in headers.get_all(FORWARDED).iter() {
        chain.extend(split_forwarded_parts(value.to_str().ok()?, b',')?);
    }
    for hop in chain.into_iter().rev() {
        let ip = forwarded_for_ip(hop)?.to_canonical();
        if !is_trusted_peer(ip, trusted) {
            return Some(ip);
        }
    }
    None
}

/// Split RFC 7239 lists or parameters only outside quoted strings. In
/// particular, an extension value may legally contain commas or semicolons;
/// those bytes must never introduce a different client address.
fn split_forwarded_parts(value: &str, delimiter: u8) -> Option<Vec<&str>> {
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    let mut parts = Vec::new();
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == delimiter {
            parts.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return None;
    }
    parts.push(&value[start..]);
    Some(parts)
}

/// Read exactly one `for` parameter from a single Forwarded hop. Reject
/// duplicate parameters and unknown/obfuscated nodes instead of trusting an
/// address beyond an ambiguous hop. RFC 7239 quotes IPv6 literals with ports.
fn forwarded_for_ip(value: &str) -> Option<IpAddr> {
    let mut address = None;
    for part in split_forwarded_parts(value, b';')? {
        let Some((name, raw)) = part.trim().split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }
        if address.is_some() {
            return None;
        }
        address = Some(raw.trim());
    }
    let raw = address?;
    let decoded;
    let rest = if let Some(quoted) = raw.strip_prefix('"') {
        let quoted = quoted.strip_suffix('"')?;
        let mut text = String::new();
        let mut chars = quoted.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => text.push(chars.next()?),
                '"' => return None,
                _ => text.push(ch),
            }
        }
        decoded = text;
        &decoded
    } else {
        raw
    };
    if let Ok(sock) = rest.parse::<std::net::SocketAddr>() {
        return Some(sock.ip());
    }
    let bare = rest
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(rest);
    bare.parse::<IpAddr>().ok()
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .or_else(|| req.extensions().get::<SocketAddr>().map(|a| a.ip()))
            .ok_or(GovernorError::UnableToExtractKey)?;

        if is_trusted_peer(peer, &self.trusted)
            && let Some(ip) = forwarded_header_ip(req.headers(), &self.trusted)
        {
            return Ok(ip);
        }
        Ok(peer)
    }
}

#[cfg(test)]
mod key_extractor_tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn forwarded_chain_uses_the_address_observed_by_the_trusted_proxy() {
        let ex = extractor(&["10.0.0.1"]);
        let req = req_from(
            "10.0.0.1:9",
            &[(
                "forwarded",
                "for=9.9.9.9;proto=https, for=203.0.113.5;proto=https",
            )],
        );
        assert_eq!(
            ex.extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn quoted_forwarded_extensions_cannot_inject_addresses_or_hops() {
        let ex = extractor(&["10.0.0.1"]);
        for value in [
            "for=203.0.113.5;ext=\"text,for=9.9.9.9\"",
            "ext=\"text;for=9.9.9.9\";for=203.0.113.5",
            r#"ext="text\",for=9.9.9.9";for=203.0.113.5"#,
        ] {
            let req = req_from("10.0.0.1:9", &[("forwarded", value)]);
            assert_eq!(
                ex.extract(&req).unwrap(),
                "203.0.113.5".parse::<IpAddr>().unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn ambiguous_or_unknown_forwarded_hops_fall_back_to_the_peer() {
        let ex = extractor(&["10.0.0.1"]);
        for value in [
            "for=9.9.9.9;for=203.0.113.5",
            "for=9.9.9.9,for=unknown",
            "for=9.9.9.9;ext=\"unclosed",
        ] {
            let req = req_from("10.0.0.1:9", &[("forwarded", value)]);
            assert_eq!(
                ex.extract(&req).unwrap(),
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "{value}"
            );
        }
    }

    #[test]
    fn quoted_ipv6_ports_and_case_insensitive_forwarded_names_are_supported() {
        let req = req_from(
            "10.0.0.1:9",
            &[("forwarded", "proto=https;FOR=\"[2001:db8::42]:443\"")],
        );
        assert_eq!(
            extractor(&["10.0.0.1"]).extract(&req).unwrap(),
            "2001:db8::42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn repeated_forwarding_headers_are_one_chain_in_wire_order() {
        let ex = extractor(&["10.0.0.1"]);
        for name in ["forwarded", "x-forwarded-for"] {
            let (forged, actual) = if name == "forwarded" {
                ("for=9.9.9.9", "for=203.0.113.5")
            } else {
                ("9.9.9.9", "203.0.113.5")
            };
            let req = req_from("10.0.0.1:9", &[(name, forged), (name, actual)]);
            assert_eq!(
                ex.extract(&req).unwrap(),
                "203.0.113.5".parse::<IpAddr>().unwrap(),
                "{name}"
            );
        }
    }

    fn req_from(peer: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = axum::http::Request::builder().uri("/api/sessions");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        let addr: SocketAddr = peer.parse().expect("valid test socket addr");
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    fn extractor(entries: &[&str]) -> TrustedProxyKeyExtractor {
        let raw: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        TrustedProxyKeyExtractor::new(parse_trusted_proxies(&raw))
    }

    #[test]
    fn untrusted_peer_is_keyed_on_the_socket_address_even_with_a_forwarded_header() {
        let ex = extractor(&[]);
        let req = req_from("203.0.113.5:9", &[("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_header_is_honored() {
        let ex = extractor(&["127.0.0.1"]);
        let req = req_from("127.0.0.1:9", &[("x-forwarded-for", "9.9.9.9")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn trusted_peer_cidr_match() {
        let ex = extractor(&["10.0.0.0/8"]);
        let req = req_from("10.1.2.3:9", &[("x-real-ip", "203.0.113.9")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn malformed_trusted_proxy_entries_are_ignored_not_fatal() {
        let ex = extractor(&["not-an-ip", "also bad/64", "127.0.0.1"]);
        // The two malformed entries were skipped; the valid one still works.
        let req = req_from("127.0.0.1:9", &[("x-real-ip", "203.0.113.9")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // And an untrusted peer is unaffected by the junk entries.
        let req = req_from("203.0.113.5:9", &[("x-real-ip", "9.9.9.9")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn ipv6_loopback_peer_is_matched_against_an_ipv6_loopback_entry() {
        let ex = extractor(&["::1"]);
        let req = req_from("[::1]:9", &[("x-forwarded-for", "2001:db8::42")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "2001:db8::42".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn x_forwarded_for_chain_skips_entries_that_are_themselves_trusted_proxies() {
        // A client behind one trusted proxy cannot plant its own value ahead
        // of what the proxy actually appended: walk right-to-left and stop
        // at the first entry that isn't itself a trusted hop.
        let ex = extractor(&["10.0.0.1"]);
        let req = req_from("10.0.0.1:9", &[("x-forwarded-for", "9.9.9.9, 10.0.0.1")]);
        assert_eq!(
            ex.extract(&req).unwrap(),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn no_connect_info_errors_instead_of_falling_back_to_headers() {
        let ex = extractor(&["127.0.0.1"]);
        let req = axum::http::Request::builder()
            .uri("/api/sessions")
            .header("x-forwarded-for", "9.9.9.9")
            .body(Body::empty())
            .unwrap();
        assert!(ex.extract(&req).is_err());
    }
}
