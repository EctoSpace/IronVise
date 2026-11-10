use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct TagsResponse {
    models: Option<Vec<ModelInfo>>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    name: Option<String>,
}

pub async fn ensure_ollama_ready(
    base_url: &str,
    model: &str,
    client: &reqwest::Client,
) -> Result<(), OllamaSetupError> {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| OllamaSetupError::OllamaNotRunning(format!("cannot reach {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(OllamaSetupError::OllamaNotRunning(format!(
            "{} returned {}",
            url,
            response.status()
        )));
    }

    let body = response.text().await.map_err(OllamaSetupError::Http)?;
    let tags: TagsResponse = serde_json::from_str(&body).map_err(OllamaSetupError::Parse)?;
    let models = tags.models.unwrap_or_default();

    let has_model = models.iter().any(|m| {
        m.name
            .as_deref()
            .map(|n| n == model || n.starts_with(&format!("{model}:")))
            .unwrap_or(false)
    });

    if has_model {
        return Ok(());
    }

    let output = Command::new("ollama")
        .arg("pull")
        .arg({
            // Disallow '/' to prevent pulling from arbitrary registries
            // (e.g. "evil.com/trojan:latest").
            static MODEL_RE: std::sync::OnceLock<regex_lite::Regex> = std::sync::OnceLock::new();
            let re = MODEL_RE.get_or_init(|| {
                regex_lite::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]*$")
                    .expect("invalid model name pattern")
            });
            if !re.is_match(model) {
                return Err(OllamaSetupError::PullFailed(format!(
                    "invalid model name '{model}': must match [a-zA-Z0-9._:-]+"
                )));
            }
            model
        })
        .output()
        .await
        .map_err(|e| OllamaSetupError::PullFailed(format!("failed to run ollama pull: {e}")))?;

    if !output.status.success() {
        return Err(OllamaSetupError::PullFailed(format!(
            "ollama pull {} exited with {:?}",
            model, output.status
        )));
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum OllamaSetupError {
    #[error("Ollama not running: {0}")]
    OllamaNotRunning(String),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("parse: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("pull failed: {0}")]
    PullFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MockServer, ScriptedResponse, generous_client};

    #[tokio::test]
    async fn is_ok_when_the_exact_model_is_already_present() {
        let server =
            MockServer::single(ScriptedResponse::ok(r#"{"models":[{"name":"mistral"}]}"#)).await;

        ensure_ollama_ready(&server.url, "mistral", &generous_client())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn is_ok_when_a_tagged_variant_matches_the_model_prefix() {
        let server = MockServer::single(ScriptedResponse::ok(
            r#"{"models":[{"name":"llama3:8b-instruct"}]}"#,
        ))
        .await;

        ensure_ollama_ready(&server.url, "llama3", &generous_client())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_an_empty_model_name_without_spawning_a_pull() {
        let server = MockServer::single(ScriptedResponse::ok(r#"{"models":[]}"#)).await;

        let err = ensure_ollama_ready(&server.url, "", &generous_client())
            .await
            .unwrap_err();
        assert!(matches!(err, OllamaSetupError::PullFailed(_)));
    }

    #[tokio::test]
    async fn rejects_a_model_name_with_a_registry_style_slash_without_spawning_a_pull() {
        let server = MockServer::single(ScriptedResponse::ok(r#"{"models":[]}"#)).await;

        let err = ensure_ollama_ready(&server.url, "evil.com/trojan", &generous_client())
            .await
            .unwrap_err();
        match err {
            OllamaSetupError::PullFailed(msg) => {
                assert!(msg.contains("evil.com/trojan"), "{msg}");
            }
            other => panic!("expected PullFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_when_the_tags_route_responds_with_a_failure_status() {
        let server = MockServer::single(ScriptedResponse::status(500, "boom")).await;

        let err = ensure_ollama_ready(&server.url, "mistral", &generous_client())
            .await
            .unwrap_err();
        match err {
            OllamaSetupError::OllamaNotRunning(msg) => assert!(msg.contains("500")),
            other => panic!("expected OllamaNotRunning, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_when_the_body_is_not_valid_json() {
        let server = MockServer::single(ScriptedResponse::ok("not json")).await;

        let err = ensure_ollama_ready(&server.url, "mistral", &generous_client())
            .await
            .unwrap_err();
        assert!(matches!(err, OllamaSetupError::Parse(_)));
    }

    #[tokio::test]
    async fn errors_when_the_server_is_unreachable() {
        let url = crate::test_support::closed_port_url();

        let err = ensure_ollama_ready(&url, "mistral", &generous_client())
            .await
            .unwrap_err();
        match err {
            OllamaSetupError::OllamaNotRunning(msg) => assert!(msg.contains("cannot reach")),
            other => panic!("expected OllamaNotRunning, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tolerates_a_response_with_no_models_field_and_still_validates_the_name() {
        let server = MockServer::single(ScriptedResponse::ok("{}")).await;

        let err = ensure_ollama_ready(&server.url, "", &generous_client())
            .await
            .unwrap_err();
        assert!(matches!(err, OllamaSetupError::PullFailed(_)));
    }
}
