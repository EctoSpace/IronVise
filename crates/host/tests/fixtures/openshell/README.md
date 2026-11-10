# OpenShell OCSF fixture

`ocsf-sample.jsonl`, one OCSF 1.8.0 record per line, as OpenShell writes them.

| Line | Source | Decision |
|---|---|---|
| 1 | Verbatim from OpenShell `docs/observability/ocsf-json-export.mdx` lines 87-132 (allowed), compacted to one line | allowed |
| 2 | Verbatim from the same file, lines 136-167 (denied; the doc sample omits `time`, `metadata`) | denied |
| 3 | Constructed per `crates/openshell-ocsf` (HTTP Activity, `container`, `metadata.uid`) | allowed |
| 4 | Constructed, network deny with `status_detail` | denied |
| 5 | Constructed audit-mode record: `action` Allowed, `message` second word `audit` (format of `crates/openshell-supervisor-network/src/proxy.rs`) | audit |
| 6 | Constructed config change (class 5019), no decision | other |
| 7 | Not JSON | malformed |
| 8 | JSON, not an object | malformed |

Lines 1-2 have no `container`, so they land in `unknown-sandbox`; lines 3-6
share sandbox `sbx-1`. Source: https://github.com/NVIDIA/OpenShell (Apache-2.0).
