# Running securely vs. running the demo

IronVise ships two very different postures. The demo image and
`docker-compose.demo.yml` are tuned for a zero-friction first run and are
**insecure by design**; a real deployment must override those defaults.

If the server is running with demo-grade settings it says so at startup:

```
WARN INSECURE DEMO MODE: semantic guard disabled (GUARD_REQUIRED=false) / dev mode on
     (ECTO_DEV_MODE=true) - and the dashboard is bound to all interfaces
     (ECTO_BIND_HOST=0.0.0.0). Do not use in production - see docs/getting-started/running-securely.md
```

## The three variables that matter

| Variable | Demo value | Hardened value | Why it matters |
|---|---|---|---|
| `GUARD_REQUIRED` | `false` | `true` | When false, the dual-LLM semantic guard never runs - intents are checked only by the policy engine, strict schema, and regex tripwires. Setting it to `true` also requires `GUARD_LLM_BACKEND` and `GUARD_LLM_MODEL`. |
| `ECTO_DEV_MODE` | `true` | unset (or `false`) | When true, an unset `DATABASE_URL` silently falls back to well-known default credentials (`ectoledger:ectoledger@localhost`). In production an unset `DATABASE_URL` should be a hard error. |
| `ECTO_BIND_HOST` | `0.0.0.0` | `127.0.0.1` | Binding to all interfaces makes the Bearer token the only thing between the network and the dashboard/API. |

A hardened launch therefore looks like:

> **A settings file can no longer switch the guard off.** The desktop GUI
> writes `.ectoledger/settings.json` (or `$ECTO_DATA_DIR/settings.json`), and
> `guard_required` there used to be read *before* the environment - so on a
> machine where the GUI had ever run, `export GUARD_REQUIRED=true` could be
> silently overridden by a stale `"guard_required": false`. `GUARD_REQUIRED` is
> now resolved most-restrictive-wins: if either source requires the guard, the
> guard is required. The server prints the effective value and its source at
> startup, and warns when the two sources disagree. The other eight keys keep
> settings-first precedence - see [configuration.md](../guides/configuration.md).

```bash
export GUARD_REQUIRED=true
export GUARD_LLM_BACKEND=ollama          # or openai / anthropic
export GUARD_LLM_MODEL="your-review-model" # choose a different model class than the primary
unset  ECTO_DEV_MODE
export ECTO_BIND_HOST=127.0.0.1
export DATABASE_URL='postgres://<user>:<pass>@<host>/<db>'   # explicit, not the dev default
export OBSERVER_TOKEN="$(openssl rand -hex 32)"              # else one is generated and printed

ironvise serve
```

For Docker, enable the guard, disable dev mode, and publish only on host loopback:

```bash
docker run --rm \
  -e GUARD_REQUIRED=true \
  -e GUARD_LLM_BACKEND=ollama -e GUARD_LLM_MODEL="your-review-model" \
  -e ECTO_DEV_MODE=false \
  -e ECTO_BIND_HOST=0.0.0.0 \
  -e DATABASE_URL='postgres://…' \
  -p 127.0.0.1:3000:3000 \
  ghcr.io/ectospace/ironvise:latest serve
```

Note the `-p 127.0.0.1:3000:3000` form: inside a container `ECTO_BIND_HOST`
must usually stay `0.0.0.0` for the port publish to work at all, so restrict
exposure at the **publish** level instead, and put TLS and a reverse proxy in
front if the dashboard needs to be reachable off-host.

## Beyond the three

Worth setting for any real deployment:

- **`ECTO_SANDBOX_PERMISSIVE`** - leave unset/`false`. Setting it to `true`
  lets actions run when the OS sandbox or a configured isolation tier fails,
  instead of aborting.
- **`OBSERVER_TOKEN`** - set explicitly rather than relying on the token
  generated and printed at startup.
- **`ECTO_CORS_ALLOWED_ORIGINS`** - leave empty unless a browser client on
  another origin genuinely needs access.
- **A configured isolation tier** - `ECTO_DOCKER_IMAGE` (any platform) or
  `ECTO_FC_BINARY` (Linux + KVM). Without one, `run_command` is bounded only
  by the in-process OS sandbox.
- **macOS**: Seatbelt denies network access to sandboxed commands; it does not
  offer per-domain allowances. See
  [sandboxing.md](../reference/sandboxing.md).

## The desktop GUI

The Tauri app runs its embedded server on `127.0.0.1` with an ephemeral port
and defaults `GUARD_REQUIRED=false`: the semantic guard is off until you turn
it on in Settings and choose its provider and model. No separate
`guard-worker` binary is needed; with the guard on, the app runs itself as
`<app> --guard-worker`. The startup banner logs the effective setting. Treat the GUI as a local operator console, not a
multi-user deployment.

Since `GUARD_REQUIRED` is resolved most-restrictive-wins, launching the GUI on
a host that exports `GUARD_REQUIRED=true` requires the guard there too, and the
Settings toggle will not turn it off. That is the intended behaviour: unset the
environment variable if you want the desktop toggle to decide.

## What the demo intentionally gives up

`docker-compose.demo.yml` additionally uses the well-known Postgres
credentials `ectoledger:ectoledger` and publishes port 3000 to your network.
It is fine for evaluating IronVise on a laptop and unfit for anything else.
