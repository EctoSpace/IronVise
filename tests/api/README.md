# API tests - black-box, against a running Rust host

These were in `sdk/python/tests/`. They are not SDK tests: they spin up a live
IronVise server and exercise its HTTP surface. Two things went wrong with that
placement, and both were real rather than tidiness complaints.

`pip install ectoledger-sdk` shipped a test suite that could not run without a
Rust toolchain and a built binary. And a regression in the *server* was reported
as "Python SDK broken", which sends whoever is triaging it to the wrong repo
directory.

They are valuable, so they moved rather than being deleted. About 3,600 lines
covering auth, boundaries, concurrency, SSE, events, sessions, policies, tokens,
webhooks and the adversarial suite.

```bash
# needs pytest, pytest-asyncio, httpx and the SDK: pip install -e sdk/python pytest pytest-asyncio httpx
# finds target/debug/ironvise (or ECTOLEDGER_BINARY); `make test-api` builds and runs it
python3 -m pytest tests/api -q
```

A server that fails to start is a test failure, not a skip (it once turned
182 tests green). The remaining skips are environmental: role-token tests
need `ECTOLEDGER_AGENT_TOKEN`/`ECTOLEDGER_AUDITOR_TOKEN`, and the
rate-limit tests skip because the fixture relaxes the limits on purpose.
2026-10-09, macOS: 168 passed, 0 failed, 14 skipped.

`conftest_adversarial.py` starts an ephemeral host, which is why it is loaded
here as a pytest plugin and no longer from the SDK's own conftest.

`conftest.py` duplicates the sample-data fixtures in `sdk/python/tests/`. That
is deliberate: the suites are independent now, and pytest has no clean way to
share a conftest across sibling roots. Ninety lines of literal sample data costs
less than coupling them back together.
