# The demo: deny it, record it, then try to change the record

```bash
make demo-hook
```

A few seconds once the binary is built. No Postgres, no model, no network - it
runs against a throwaway SQLite ledger in a temp directory and cleans up after
itself. The recording below is deliberately slowed so it can be followed; see
*Re-recording*.

![the demo](../../docs/assets/hook-denial-demo.gif)

## What it shows

1. Claude Code proposes `ls -la`. The `PreToolUse` hook returns `allow`.
2. Claude Code proposes `rm -rf /`. The hook returns **`deny`** - Claude Code
   honours that and the command never runs.
3. The refusal is in the ledger as a `tripwire_rejection` event with
   `enforced: true`, hash-chained to the events before it.
4. `verify-session` passes.
5. One field of the recorded denial is rewritten in the database, so the ledger
   now says the command looked fine.
6. `verify-session` fails.

Step 2 is the part most audit tooling cannot do. A log written after the fact
tells you what an agent did; the hook decides whether it happens at all. Only pre-execution integrations (the Claude Code, Codex and Antigravity hooks,
`mcp-proxy`, and the native loop) can enforce - the recording proxy sees text,
not tool calls, and cannot block. [`docs/guides/integrations.md`](../../docs/guides/integrations.md)
sets out which surface can do what, claim by claim.

## Why it is a script and not just a recording

Every step asserts. If the hook stopped denying, if the denial stopped being
recorded as enforced, or if tampering stopped being detected, the script exits
non-zero. So it is an end-to-end test of the hook, the ledger and the verifier
together, and the recording is merely a rendering of a run that passed.

Demos that exist only as a GIF drift away from the software. This one cannot
drift without failing.

## Re-recording

```bash
make demo-hook-record     # needs asciinema and agg
```

`DEMO_PACE=1` inserts the pauses that make it watchable. Without it the script
runs flat out, which is what you want when running it as a test.

## What it does not show

That the log is complete. A hash chain constrains what can happen *after* an
event is written; it says nothing about an event that was never written. The
demo tampers with an existing record because that is the property the chain
actually provides - and the honest claim is the narrower one.
