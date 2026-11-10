mod qa_server_common;

use qa_server_common::{ADMIN_TOKEN, bearer, spawn_server, spawn_server_with_trusted_proxies};

fn pin_low_limits() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| unsafe {
        std::env::set_var("API_RATE_LIMIT_PER_SECOND", "1");
        std::env::set_var("API_RATE_LIMIT_BURST", "3");
        std::env::set_var("SESSION_RATE_LIMIT_PER_SECOND", "1");
        std::env::set_var("SESSION_RATE_LIMIT_BURST", "2");
        std::env::set_var("SSE_RATE_LIMIT_PER_SECOND", "1");
        std::env::set_var("SSE_RATE_LIMIT_BURST", "2");
    });
}

fn assert_429_shape(resp: &reqwest::Response) {
    assert!(
        resp.headers().contains_key("retry-after")
            || resp.headers().contains_key("x-ratelimit-after"),
        "429 response is missing a retry hint header"
    );
}

#[tokio::test]
async fn api_governor_returns_429_after_burst() {
    pin_low_limits();
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let mut statuses = Vec::new();
    for _ in 0..8 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .send()
            .await
            .unwrap();
        statuses.push(resp.status());
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            assert_429_shape(&resp);
            let body = resp.text().await.unwrap();
            assert!(body.contains("Wait for"), "unexpected 429 body: {body}");
            return;
        }
    }
    panic!("expected a 429 among {statuses:?}");
}

#[tokio::test]
async fn session_create_governor_returns_429_after_burst() {
    pin_low_limits();
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let mut saw_429 = false;
    for _ in 0..6 {
        let resp = client
            .post(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .json(&serde_json::json!({ "goal": "qa", "record": true }))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            assert_429_shape(&resp);
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected the session-create limiter to trip");
}

#[tokio::test]
async fn sse_governor_returns_429_after_burst() {
    pin_low_limits();
    let base = spawn_server().await;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let mut saw_429 = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/stream"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            assert_429_shape(&resp);
            saw_429 = true;
            break;
        }
    }
    assert!(saw_429, "expected the SSE limiter to trip");
}

/// By default (no `ECTO_TRUSTED_PROXIES`) nothing is a trusted proxy, so the
/// rate limiter must key on the TCP peer address regardless of what any of
/// the three forwarding headers claim - a direct caller cannot evade its
/// own exhausted limit by sending a fresh spoofed header per request.
#[tokio::test]
async fn spoofed_forwarding_headers_do_not_bypass_rate_limiting_by_default() {
    pin_low_limits();
    let base = spawn_server().await;
    let client = reqwest::Client::new();
    let mut tripped = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "limiter never tripped from the real client identity"
    );

    for (header, value) in [
        ("X-Forwarded-For", "203.0.113.9"),
        ("X-Real-Ip", "203.0.113.10"),
        ("Forwarded", "for=203.0.113.11"),
    ] {
        let spoofed = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .header(header, value)
            .send()
            .await
            .unwrap();
        assert_eq!(
            spoofed.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "a spoofed {header} header let the caller evade its own exhausted rate limit"
        );
    }
}

/// When the direct peer *is* a configured trusted proxy, the header it sets
/// is honored: two distinct client IPs behind that proxy get independent
/// limits instead of sharing the proxy's own exhausted one.
#[tokio::test]
async fn trusted_proxy_header_is_honored_for_rate_limiting() {
    pin_low_limits();
    let base = spawn_server_with_trusted_proxies("127.0.0.1", &["127.0.0.1"]).await;
    let client = reqwest::Client::new();

    let mut tripped = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .header("X-Forwarded-For", "203.0.113.20")
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "client .20 behind the trusted proxy never tripped its own limit"
    );

    let other_client = client
        .get(format!("{base}/api/sessions"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .header("X-Forwarded-For", "203.0.113.21")
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_client.status(),
        reqwest::StatusCode::OK,
        "a different client behind the same trusted proxy must have its own limit"
    );
}

/// `ECTO_TRUSTED_PROXIES` entries are IPs or CIDRs; a CIDR must match any
/// peer address it covers, not just an exact string.
#[tokio::test]
async fn trusted_proxy_cidr_entry_matches_the_peer() {
    pin_low_limits();
    let base = spawn_server_with_trusted_proxies("127.0.0.1", &["127.0.0.0/8"]).await;
    let client = reqwest::Client::new();

    let mut tripped = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .header("X-Forwarded-For", "203.0.113.30")
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "peer covered by the 127.0.0.0/8 CIDR was not treated as a trusted proxy"
    );

    let other_client = client
        .get(format!("{base}/api/sessions"))
        .header("Authorization", bearer(ADMIN_TOKEN))
        .header("X-Forwarded-For", "203.0.113.31")
        .send()
        .await
        .unwrap();
    assert_eq!(
        other_client.status(),
        reqwest::StatusCode::OK,
        "a different client behind the CIDR-matched proxy must have its own limit"
    );
}

/// A malformed entry in `ECTO_TRUSTED_PROXIES` must not take the server
/// down or block the other, valid entries in the same list.
#[tokio::test]
async fn malformed_trusted_proxy_entries_are_ignored() {
    pin_low_limits();
    let base =
        spawn_server_with_trusted_proxies("127.0.0.1", &["not-an-ip", "", "127.0.0.1"]).await;
    let client = reqwest::Client::new();

    let mut tripped = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .header("X-Forwarded-For", "203.0.113.40")
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(
        tripped,
        "the valid '127.0.0.1' entry must still work alongside the malformed ones"
    );
}

/// The trusted-proxy check must work for an IPv6 peer too, not just IPv4.
#[tokio::test]
async fn ipv6_loopback_peer_can_be_a_trusted_proxy() {
    pin_low_limits();
    let base = spawn_server_with_trusted_proxies("::1", &["::1"]).await;
    let client = reqwest::Client::new();

    let mut tripped = false;
    for _ in 0..6 {
        let resp = client
            .get(format!("{base}/api/sessions"))
            .header("Authorization", bearer(ADMIN_TOKEN))
            .header("X-Forwarded-For", "203.0.113.50")
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tripped = true;
            break;
        }
    }
    assert!(tripped, "IPv6 loopback peer was not trusted as configured");
}
