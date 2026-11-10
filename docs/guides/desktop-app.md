# The desktop app

The desktop app (`gui/`, Tauri 2) is IronVise with its server built in: it
starts an embedded backend on a random local port with its own SQLite ledger,
and every screen talks to that backend. Nothing listens beyond `127.0.0.1`.

This page goes screen by screen: what each option does, where it is stored,
and what to do when something does not work. For the same settings as
environment variables, see [configuration.md](configuration.md).

## Where things are kept

| What | Where |
|---|---|
| Ledger (sessions, events, signatures) | `ectoledger.db` in the app data folder |
| Settings | `settings.json` in the app data folder |
| API keys entered in Settings | The OS credential store: macOS Keychain, Windows Credential Manager, or the Secret Service on Linux. Never in `settings.json`. |
| Tripwire and policies | `tripwire.json` and `policies/*.toml` in the app data folder, edited on their screens; the policy for new runs is `active_policy` in `settings.json` |

The app data folder is `~/Library/Application Support/io.ectoledger.agent-ledger`
on macOS, `%APPDATA%\io.ectoledger.agent-ledger` on Windows and
`~/.local/share/io.ectoledger.agent-ledger` on Linux. Point the CLI at the same
folder with `ECTO_DATA_DIR` to share settings with it. The Linux installer
package was renamed from `ecto-ledger` to `iron-vise`. That rename does not
move this folder: it follows the bundle identifier, which is still
`io.ectoledger.agent-ledger`.

## First start: the setup wizard

The wizard runs once. **Express** uses the embedded SQLite ledger and a local
Ollama if one is installed or running. **Custom** asks three things:

1. **Database**: PostgreSQL (a URL), SQLite (embedded, the default for one
   machine), or in-memory (lost on restart, for trying things out).
2. **Model provider**:
   - *Install Ollama locally* or *Connect existing local LLM* (Ollama). The next
     step lists the models Ollama has and pulls the one you choose.
   - *Anthropic* or *OpenAI*. Paste the API key (it goes to the credential
     store), then choose a model from the list the provider returns. Other
     OpenAI-compatible servers (LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI) are
     set up afterwards in Settings.
3. **Provisioning**: saves the choices and, for Ollama, pulls the model.

Everything the wizard sets can be changed later in Settings.

## Command palette

⌘K (macOS) or Ctrl+K (elsewhere) opens it from anywhere in the app; the
sidebar also has a **Search…** button showing the shortcut. It lists every
screen the sidebar can currently reach (so Testing, Prometheus, Live Feed and
Dev Hub only appear once developer tools are on), every Settings section -
picking one opens Settings and scrolls to and focuses that section - and a
few actions: switching the Appearance theme to Dark, Light or System, and
(with developer tools on) opening the developer console. Type to filter by
label or keyword; arrow keys move the selection, Enter opens it, Esc closes
and returns focus to wherever it was.

## Home

Type a goal and **Run** to start an audit session: the agent proposes one
action at a time; tripwire, policy and (if on) the semantic guard check each
one before it runs; every step is signed into the ledger. The panel below shows
the session's events as they arrive. When a policy asks for human approval, the
run pauses on an **Approval required** card: approve or deny, with an optional
reason, and the decision is signed into the session.

Home → Run needs a ledger that supports the agent loop (SQLite or PostgreSQL;
Settings → Ledger says which is live) and a model (Settings → Model).

## History

Every session, newest first, with its status. Select one to see its events.

- **Verify** re-checks the hash chain and every event signature.
- **Certificate** exports an `.elc` file anyone can check offline with
  `verify-cert` or the browser verifier. After saving, the app says how it is
  signed: by the session's key, countersigned by this installation's issuer
  key, or unsigned. Audit runs rotate their key, so their certificates are
  unsigned unless the installation has an issuer key; the message gives the
  one command that creates it (`ironvise issuer-key init`).
- **Report** saves a report of the session; **Verifiable Credential** shows the
  W3C credential issued when a session completes.

## Policy

Policy files (TOML) for the agent: rules on actions, observations, approvals
and step limits. See `audit_policy.example.toml` for every rule.

- **Use for new runs** makes the selected policy the one Home → Run checks
  every action against; **Stop using** goes back to none. The file is read
  when each run starts, so a saved edit applies to the next run, and the
  session records that policy's hash (shown in its certificate). With no
  policy chosen, runs are checked by tripwire (and the guard, if on) only,
  and record no policy.
- **Save** checks that the text loads as a policy, not just as TOML, and says
  what is wrong. **Delete** removes a policy that is not in use.
- The four built-in packs (SOC 2, PCI DSS, OWASP Top 10, ISO 42001) are read
  only; use one as is, or copy its text into a new policy.
- If the environment sets `ECTO_POLICY_PATH`, that policy wins and the screen
  says so.

## Tripwire

The deterministic checks every action passes before it runs:

- **Allowed paths**: where file actions may read and write.
- **Allowed domains (HTTP)**: hosts the agent may fetch from. This is the one
  domain list that is enforced.
- **Banned command patterns**: regular expressions; a matching command is
  refused.
- **Minimum justification** length, and **Require HTTPS** (plain HTTP refused).

**Try a command** checks a command against the saved rules and names the rule
that refused it. Unsaved edits are not checked until you save.

## Access

- **API tokens** for the REST API and the dashboard, with a role (agent or
  auditor) and an optional expiry. A token is shown once, when it is created;
  only its hash is kept. Admin tokens cannot be created here.
- **Webhooks** forward ledger events to a SIEM or any HTTPS endpoint: the URL,
  an optional bearer token, the format, which event kinds to send, and whether
  it starts enabled.

## Settings

Changes are saved with **Save** in the bar at the bottom; **Discard** reloads
what is saved. Model and guard changes apply to the next session; a database
change applies after a restart. Emptying a field and saving removes it from
`settings.json`, so the environment or the built-in default applies again.

The **Search settings** field at the top filters as you type: a query that
matches a section's name (e.g. "guard") shows that section in full, and a
query that only matches a field's label or a word associated with it (e.g.
"postgres" finds the database field, "theme" finds Appearance) shows just
that field. The on-page index on the left follows the same filter. No match
shows a "No settings match" message with a link to clear the search; Esc in
the field clears it too.

### Ledger

Shows which ledger is live. **Database for the next start**: a PostgreSQL URL,
or empty for the embedded SQLite ledger.

### Model

- **Provider**: Ollama, LM Studio, llama.cpp, vLLM, MLX-LM, LocalAI, OpenAI,
  Anthropic, Google Gemini, Azure OpenAI, Mistral AI, Groq, OpenRouter,
  DeepSeek, xAI, or a custom OpenAI-compatible server.
- **Model**: chosen from the models the provider lists, and only those. Models
  that cannot chat (embedding, speech, image) are left out. **Refresh** asks
  the provider again. If the provider lists nothing, the field stays empty
  until it does; start the server or load a model there, check the address,
  then Refresh. Switching provider clears the model so it is chosen again.
- **API key** (all nine hosted presets - OpenAI, Anthropic, Gemini, Azure
  OpenAI, Mistral, Groq, OpenRouter, DeepSeek, and xAI): saved to the OS
  credential store and never shown again; **Remove** deletes it. A key saved
  here wins over the provider's `*_API_KEY` in the environment, which still
  works. The status line says which one is in use.
- **Address** (all but Anthropic): where the server listens, e.g.
  `http://127.0.0.1:11434` for Ollama or `http://localhost:1234/v1` for LM
  Studio. Addresses typed here must be on this machine; set a remote one
  through the environment. **Test connection** checks it and lists the models.

### Semantic guard

Off by default. When on, a second model reads each proposed action against the
session goal and can refuse it, on top of tripwire and policy. It runs in a
separate process (the app starts a copy of itself as the guard worker) and
fails closed: if its model cannot be reached, every action is refused.

Choose the guard's **provider** and **model** explicitly; turning the guard on
starts from the agent's provider, and Save refuses a guard without a model. A
small, fast model is enough. If the environment sets `GUARD_REQUIRED`, the
stricter of the two values applies and the section says so.

### Agent, Desktop, Environment

- **Max steps per session**: the agent loop stops after this many actions.
- **Appearance**: Dark, Light, or Match system. Applies at once and is stored
  on this device (not in `settings.json`), so it does not travel with an
  exported config or to another machine.
- **Show developer tools**: adds Testing, Prometheus, Live Feed and Dev Hub to
  the sidebar (for maintainers).
- **From the environment**: the sandbox in use (Firecracker, Docker/Podman or
  none). It is set through the environment before launch.

## Troubleshooting

| You see | What to do |
|---|---|
| Model: "This provider listed no models" | Start the provider (and, for LM Studio, load a model and start its server), check the address, then Refresh. Hosted providers need an API key first. |
| Test connection: "refused the request (401)" | The API key is wrong or missing. Save it again in Settings → Model. |
| "Base URL must point at localhost" | Addresses typed in the app must be on this machine. Use the environment (`OLLAMA_BASE_URL`, `OPENAI_BASE_URL`) for a remote server. |
| Every action is refused with the guard on | The guard's model cannot be reached or is not chosen. Check Settings → Semantic guard, or turn it off. |
| macOS asks whether IronVise may use its keychain item | After installing a new build, macOS may ask once. Allow it, or enter the key again. |
| "IronVise could not open its ledger" at start | Your data has not been changed. Do not delete the file; keep it and report the message with the version you upgraded from. |
| A certificate is "unsigned" | Expected for audit runs without an issuer key; see History above. |
