//! The shared enforcement path: policy → tripwire → guard, with no side effects.
//!
//! Three surfaces need to answer "may this action run?" - the native cognitive
//! loop, the Claude Code `PreToolUse` hook, and the SDK's `verify_intent`
//! endpoint. They share one implementation so that "the guard denied it" means
//! the same thing whichever door the request came through.
//!
//! [`evaluate_intent`] is therefore deliberately **pure**. It writes nothing,
//! executes nothing, and touches no database. Callers decide what to record and
//! what to do with the verdict.
//!
//! ## Fail-closed
//!
//! A guard that errors returns [`Verdict::Deny`], matching the cognitive loop.
//! An unreachable or broken guard must never widen what is permitted.

use ectoledger_core::intent::ProposedIntent;
use serde::Serialize;

use crate::guard::{GuardDecision, GuardExecutor};
use crate::policy::PolicyEngine;
use crate::tripwire::Tripwire;

/// Which check refused the action. Recorded so an auditor can tell a policy
/// decision from a pattern match from a model judgement, rather than reading
/// all three as one undifferentiated "denied".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyStage {
    /// The declarative policy engine refused it.
    Policy,
    /// A tripwire, path rule, or schema check refused it.
    Tripwire,
    /// The semantic guard refused it.
    Guard,
    /// The guard could not be consulted. Fail-closed: treated as a denial.
    GuardUnavailable,
}

impl DenyStage {
    /// Stable identifier, used for the `stage` field of ledger events and for
    /// the API surface.
    pub fn as_str(self) -> &'static str {
        match self {
            DenyStage::Policy => "policy",
            DenyStage::Tripwire => "tripwire",
            DenyStage::Guard => "guard",
            DenyStage::GuardUnavailable => "guard_unavailable",
        }
    }

    /// True when the refusal came from the semantic guard rather than a
    /// deterministic rule. Callers record these as `guard_denial` and the rest
    /// as `tripwire_rejection`.
    pub fn is_guard(self) -> bool {
        matches!(self, DenyStage::Guard | DenyStage::GuardUnavailable)
    }
}

/// The outcome of evaluating a proposed action. Carries no side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny { reason: String, stage: DenyStage },
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

/// Everything the evaluator is allowed to consult.
///
/// Borrowed rather than owned so the caller keeps ownership of long-lived
/// state, and so a caller with no policy or no guard configured can pass
/// `None` without constructing a placeholder that might behave differently.
pub struct EvaluationContext<'a> {
    pub policy: Option<&'a PolicyEngine>,
    pub tripwire: &'a Tripwire,
    /// The session goal, which the guard uses to judge whether the action is
    /// on-task. Empty is allowed but weakens the guard's semantic check.
    pub goal: &'a str,
    /// Step index, for policy rules that are step-sensitive. Surfaces without a
    /// meaningful step counter pass 0.
    pub step: u32,
    /// Whether a semantic guard is *required* for this evaluation to count.
    ///
    /// A field rather than a read of [`crate::config::guard_required`] so the
    /// evaluator stays pure and the decision is testable - and so that adding a
    /// surface is a compile error until its author decides what happens when the
    /// guard is required and absent. Passing `guard: None` with this set to
    /// `true` denies; the alternative is returning an allow that reports
    /// protections it did not apply.
    pub guard_required: bool,
}

/// Which layers an evaluation actually ran, and which it did not.
///
/// Sharing an evaluator is not the same as sharing its configuration. Returned
/// alongside a verdict so a caller can tell a full evaluation from a
/// tripwire-only preflight instead of reading `"decision": "allow"` as though
/// every layer had spoken.
#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    /// Layers consulted, in pipeline order: `policy`, `tripwire`, `guard`.
    pub evaluated: Vec<&'static str>,
    /// Layers that were not consulted on this surface.
    pub skipped: Vec<&'static str>,
    /// SHA-256 of the policy file that produced the decision, when one was
    /// evaluated. An auditor cannot check a decision against rules they cannot
    /// identify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

impl Coverage {
    pub fn new(policy_hash: Option<String>, guard_present: bool) -> Self {
        let mut evaluated = Vec::new();
        let mut skipped = Vec::new();
        if policy_hash.is_some() {
            evaluated.push("policy");
        } else {
            skipped.push("policy");
        }
        evaluated.push("tripwire");
        if guard_present {
            evaluated.push("guard");
        } else {
            skipped.push("guard");
        }
        Self {
            evaluated,
            skipped,
            policy_hash,
        }
    }
}

/// Run policy → tripwire → guard against a proposed action.
///
/// Order matches the cognitive loop and is not arbitrary: the cheap
/// deterministic checks run before the expensive model call, so an action the
/// policy already forbids never costs a guard round-trip, and the recorded
/// reason names the first rule that refused rather than the last.
/// The guard is a separate parameter rather than a context field because
/// [`GuardExecutor::evaluate`] takes `&mut self` - both implementations, the
/// in-process LLM guard and the guard-worker subprocess, need exclusive access -
/// and a shared-borrow context cannot carry it. Taking the trait rather than the
/// concrete `Guard` also lets the hook endpoint reuse the `GuardProcess` the
/// REST path already spawns, instead of building a second, differently
/// configured guard.
pub async fn evaluate_intent(
    ctx: &EvaluationContext<'_>,
    guard: Option<&mut dyn GuardExecutor>,
    intent: &ProposedIntent,
) -> Verdict {
    // 1. Declarative policy.
    if let Some(policy) = ctx.policy
        && let Err(violation) = policy.validate_intent(intent, ctx.step)
    {
        return Verdict::Deny {
            reason: violation.to_string(),
            stage: DenyStage::Policy,
        };
    }

    // 2. Tripwires, path and schema rules.
    if let Err(e) = ctx.tripwire.validate(intent) {
        return Verdict::Deny {
            reason: e.to_string(),
            stage: DenyStage::Tripwire,
        };
    }

    // 3. Semantic guard, when one is configured.
    let Some(guard) = guard else {
        if ctx.guard_required {
            // Fail-closed. An allow here would report the protections of a
            // configuration that is not running.
            return Verdict::Deny {
                reason: "the semantic guard is required (GUARD_REQUIRED) but none is \
                         running (the server log says why), so the action was not \
                         evaluated against it"
                    .to_string(),
                stage: DenyStage::GuardUnavailable,
            };
        }
        return Verdict::Allow;
    };

    match guard.evaluate(ctx.goal, intent).await {
        Ok(GuardDecision::Allow) => Verdict::Allow,
        Ok(GuardDecision::Deny { reason }) => Verdict::Deny {
            reason,
            stage: DenyStage::Guard,
        },
        // Fail-closed, matching the loop. A guard that cannot be reached is not
        // a guard that approves.
        Err(e) => Verdict::Deny {
            reason: format!("guard error (fail-closed): {e}"),
            stage: DenyStage::GuardUnavailable,
        },
    }
}

#[cfg(test)]
mod tests;
