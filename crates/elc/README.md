# ectoledger-elc

The `.elc` audit certificate format and its offline verifier. One
implementation, used by `verify-cert`, `ironvise verify-certificate` and the
browser verifier (`crates/elc-wasm`, served from `site/verify.html`).

No database, no network, no async runtime. It builds for
`wasm32-unknown-unknown` unchanged; keep it that way.

The format is specified in [`docs/reference/elc-spec.md`](../../docs/reference/elc-spec.md). A
second verifier written from that spec alone lives in
[`examples/verified-session/verify_elc.py`](../../examples/verified-session/verify_elc.py).

Running the verifier, or implementing the format, is covered by the
"verification is not production use" grant in the root `LICENSE`.
