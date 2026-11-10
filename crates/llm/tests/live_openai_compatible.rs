//! Live checks against a real OpenAI-compatible server.
//!
//! Ignored by default - they need a model server listening. Run with:
//!
//!   ECTO_LIVE_BASE_URL=http://127.0.0.1:1234/v1 \
//!   ECTO_LIVE_MODEL=qwen2.5-7b-instruct \
//!     cargo test -p ectoledger-llm --test live_openai_compatible -- --ignored --nocapture
//!
//! Point `ECTO_LIVE_BASE_URL` at LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI or
//! anything else speaking the same wire format. Nothing here is specific to a
//! particular server, and no server is assumed to be present: one code path
//! serves all of them, so hardcoding any single one would undo the thing being
//! tested.
//!
//! `ECTO_LIVE_BASE_URL` is deliberately documented **with** the `/v1` suffix,
//! because that is the string LM Studio and llama.cpp print for their users
//! and the one that used to produce `/v1/v1/chat/completions` and a 404.

use ectoledger_llm::{LlmBackend, OpenAiBackend};

fn live_config() -> Option<(String, String)> {
    let base = std::env::var("ECTO_LIVE_BASE_URL").ok()?;
    let model = std::env::var("ECTO_LIVE_MODEL").ok()?;
    Some((base, model))
}

/// Skip rather than fail when a server is not configured.
///
/// All the cases here live in one file, and `--ignored` runs the file. Pointing
/// the suite at llama.cpp should not fail because Ollama's variables happen to
/// be unset - a red run for a server you did not ask about trains people to
/// ignore red runs.
macro_rules! skip_unless {
    ($cfg:expr, $what:literal) => {
        match $cfg {
            Some(v) => v,
            None => {
                println!("SKIP: {} is not configured", $what);
                return;
            }
        }
    };
}

fn backend(base: &str, model: &str) -> OpenAiBackend {
    // Configure through the environment, as the host does.
    unsafe {
        std::env::set_var("OPENAI_BASE_URL", base);
        std::env::set_var("OPENAI_MODEL", model);
    }
    OpenAiBackend::from_env(&reqwest::Client::new())
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible server; see the module docs"]
async fn the_server_is_reachable_and_lists_models() {
    let (base, model) = skip_unless!(live_config(), "ECTO_LIVE_BASE_URL/MODEL");
    let client = reqwest::Client::new();
    let be = backend(&base, &model);

    be.ensure_ready(&client)
        .await
        .expect("ensure_ready against a running server");

    let models = be.list_models(&client).await.expect("list_models");
    println!("LIVE_MODELS={}", models.join(", "));
    assert!(
        !models.is_empty(),
        "a running server should report at least one model"
    );
    assert!(
        models.iter().any(|m| m == &model),
        "configured model {model:?} not offered by the server: {models:?}"
    );
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible server; see the module docs"]
async fn a_base_url_that_already_ends_in_v1_does_not_404() {
    // The regression this phase exists for. Before the fix, a base URL ending in
    // /v1 produced /v1/v1/chat/completions. A 404 here means the normaliser is
    // not wired into the request path.
    let (base, model) = skip_unless!(live_config(), "ECTO_LIVE_BASE_URL/MODEL");
    assert!(
        base.trim_end_matches('/').ends_with("/v1"),
        "this test is only meaningful with a base URL that already ends in /v1"
    );

    let be = backend(&base, &model);
    let raw = be
        .raw_call("Reply with the single word: ok", "Say ok.")
        .await
        .expect("chat completion against a /v1 base URL");

    println!(
        "LIVE_RAW={}",
        raw.trim().chars().take(120).collect::<String>()
    );
    assert!(
        !raw.trim().is_empty(),
        "server returned an empty completion"
    );
}

#[tokio::test]
#[ignore = "needs a live OpenAI-compatible server; see the module docs"]
async fn a_real_model_produces_a_usable_proposed_intent() {
    // End-to-end for the agent loop's actual entry point: JSON mode, fence
    // stripping and justification repair all have to hold against a real
    // model's output, not a fixture.
    let (base, model) = skip_unless!(live_config(), "ECTO_LIVE_BASE_URL/MODEL");
    let be = backend(&base, &model);

    let intent = be
        .propose(
            ectoledger_llm::DEFAULT_SYSTEM_PROMPT,
            "Current goal: Audit server_config.txt for misconfigurations\n\n\
             Recent events:\n  [genesis] initialized",
        )
        .await
        .expect("propose against a live model");

    println!(
        "LIVE_INTENT action={} justification_len={}",
        intent.action,
        intent.justification.len()
    );
    assert!(!intent.action.trim().is_empty(), "intent has no action");
    // The repair guarantees this regardless of what the model omitted, which is
    // the whole reason it is shared across backends.
    assert!(
        !intent.justification.trim().is_empty(),
        "justification repair did not fill an empty justification"
    );
}

//
// Justification repair is a shared helper used by every backend; this checks
// it against a real model.
//
//   ECTO_LIVE_OLLAMA_URL=http://127.0.0.1:11434 \
//   ECTO_LIVE_OLLAMA_MODEL=<a pulled model> \
//     cargo test -p ectoledger-llm --test live_openai_compatible -- --ignored --nocapture

#[tokio::test]
#[ignore = "needs a live Ollama; see the module docs"]
async fn ollama_still_repairs_justification_after_the_refactor() {
    let (base, model) = skip_unless!(
        std::env::var("ECTO_LIVE_OLLAMA_URL")
            .ok()
            .zip(std::env::var("ECTO_LIVE_OLLAMA_MODEL").ok()),
        "ECTO_LIVE_OLLAMA_URL/MODEL"
    );
    unsafe {
        std::env::set_var("OLLAMA_BASE_URL", &base);
        std::env::set_var("OLLAMA_MODEL", &model);
    }
    let be = ectoledger_llm::OllamaBackend::from_env(&reqwest::Client::new());

    let models = be
        .list_models(&reqwest::Client::new())
        .await
        .expect("list_models via /api/tags");
    println!("LIVE_OLLAMA_MODELS={}", models.join(", "));
    assert!(!models.is_empty(), "Ollama reported no models");

    let intent = be
        .propose(
            ectoledger_llm::DEFAULT_SYSTEM_PROMPT,
            "Current goal: Audit server_config.txt for misconfigurations\n\n\
             Recent events:\n  [genesis] initialized",
        )
        .await
        .expect("propose against a live Ollama model");

    println!(
        "LIVE_OLLAMA_INTENT action={} justification_len={}",
        intent.action,
        intent.justification.len()
    );
    assert!(!intent.action.trim().is_empty());
    assert!(
        !intent.justification.trim().is_empty(),
        "shared repair did not fill the justification on the Ollama path"
    );
}
