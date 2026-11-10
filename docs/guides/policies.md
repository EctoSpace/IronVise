# Policies

A policy is a TOML file that says what an agent may do during an audit: which
actions and commands are allowed, which are forbidden, which checks must run,
what to redact from output, and where a human must approve.

## Applying a policy

| Surface | How |
|---|---|
| CLI | `ironvise audit "<goal>" --policy path/to/policy.toml` |
| Observer (hook, SDK `verify-intent`, REST runs) | `ECTO_POLICY_PATH=/path/to/policy.toml` before `ironvise serve` |
| Desktop app | Policy screen, **Use for new runs** (stored as `active_policy`) |

If `ECTO_POLICY_PATH` is set but the file is missing or invalid, the server
refuses to start rather than running without the policy. Each verdict reports
the SHA-256 of the policy it was checked against. Details are in
[configuration.md](configuration.md#ecto_policy_path---the-servers-declarative-policy).

## Built-in packs

`crates/host/policies/` ships ready-made packs:

| File | Standard | Usable as a run policy |
|---|---|---|
| `soc2-audit.toml` | SOC 2 | Yes |
| `pci-dss-audit.toml` | PCI DSS | Yes |
| `owasp-top10.toml` | OWASP Top 10 | Yes |
| `iso42001.toml` | ISO/IEC 42001 | No, it maps controls to ledger evidence and has no action rules |

```bash
ironvise audit "Verify SOC 2 controls on this server" \
  --policy crates/host/policies/soc2-audit.toml
```

## Writing your own

Start from [`audit_policy.example.toml`](../../audit_policy.example.toml) or a
copy of a pack. All keys are top level; do not wrap them in a `[policy]` table.

| Key | Purpose |
|---|---|
| `name`, `goal` | Describe the audit |
| `max_steps` | Step budget for the agent |
| `[[required_checks]]` | Checks you expect the audit to cover. Stored with the policy; not enforced in 0.8 |
| `[[allowed_actions]]`, `[[forbidden_actions]]` | Restrict the action surface (paths, commands, domains) |
| `[[command_rules]]` | Regex allow or deny rules for commands |
| `[[observation_rules]]` | Redact or flag sensitive patterns in tool output |
| `[[approval_gates]]` | Require human sign-off before high-risk steps |
| `[[plugins]]` | Third-party security tools the agent may run |
| `[findings]` | Evidence requirements per severity |

The policy is one layer. The tripwire, the dual-LLM guard and the sandbox apply
independently; see [integrations.md](integrations.md) and
[threat-model.md](../reference/threat-model.md).
