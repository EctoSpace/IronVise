//! `http_get`: a bounded GET of a URL the tripwire approved.

use super::*;

pub(super) const HTTP_TIMEOUT_SECS: u64 = 10;
pub(super) const HTTP_MAX_BODY_BYTES: usize = 64 * 1024;

pub(super) async fn http_get(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let url = validated
        .params()
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("url"))?;

    // SSRF protection: reject internal / link-local / cloud-metadata targets.
    let parsed = url::Url::parse(url)
        .map_err(|e| ExecuteError::InvalidCommand(format!("http_get: invalid URL '{url}': {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(ExecuteError::InvalidCommand(format!(
            "http_get: disallowed URL scheme '{scheme}'"
        )));
    }
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(host) = parsed.host_str() {
        // Block well-known metadata hostnames before touching DNS.
        if host == "metadata.google.internal"
            || host.ends_with(".internal")
            || host.ends_with(".local")
            || host == "localhost"
        {
            return Err(ExecuteError::InvalidCommand(format!(
                "http_get: URL host '{host}' is disallowed (internal host)"
            )));
        }
        // Resolve the hostname to catch DNS-rebinding and private IP targets.
        // Fail closed: an unresolvable host is an error, not a skipped check.
        let port = parsed.port_or_known_default().unwrap_or(80);
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                ExecuteError::InvalidCommand(format!("http_get: cannot resolve host '{host}': {e}"))
            })?
            .collect();
        if addrs.is_empty() {
            return Err(ExecuteError::InvalidCommand(format!(
                "http_get: host '{host}' resolved to no addresses"
            )));
        }
        for addr in &addrs {
            let ip = addr.ip();
            let is_private = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                }
                std::net::IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || v6.to_ipv4_mapped().is_some_and(|v4| {
                            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                        })
                }
            };
            if is_private {
                return Err(ExecuteError::InvalidCommand(format!(
                    "http_get: URL '{url}' resolves to internal address {ip} (SSRF blocked)"
                )));
            }
        }
        // Pin the request to the addresses validated above. Without this,
        // reqwest re-resolves the hostname at connect time and a rebinding
        // DNS server could return an internal address for the second lookup
        // (check/use race).
        client_builder = client_builder.resolve_to_addrs(host, &addrs);
    }

    let client = client_builder.build().map_err(ExecuteError::Http)?;
    let response = client.get(url).send().await.map_err(ExecuteError::Http)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ExecuteError::Http)?;
    if body.len() > HTTP_MAX_BODY_BYTES {
        return Ok(format!(
            "status: {}; body too large ({} bytes); first {} bytes: {}",
            status,
            body.len(),
            HTTP_MAX_BODY_BYTES,
            String::from_utf8_lossy(&body[..HTTP_MAX_BODY_BYTES.min(body.len())])
        ));
    }
    let text = String::from_utf8_lossy(&body).to_string();
    Ok(format!("status: {status}; body: {text}"))
}
