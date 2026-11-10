// Browser verifier for IronVise audit certificates (.elc).
//
// The checks run in WebAssembly built from crates/elc-wasm, which wraps the
// same Rust function the verify-cert command calls. This file only moves bytes
// in and out of the module and draws the result. It never sends anything
// anywhere, and the page's Content-Security-Policy (connect-src 'none') would
// stop it if it tried.
//
// Everything taken from a certificate is untrusted: a forged file controls its
// goal, its titles and its hashes. It is written with textContent only.

(function () {
  "use strict";

  const B = window.ELC_BUNDLE;
  const $ = (id) => document.getElementById(id);
  const FLAG_STRICT = 1;
  const FLAG_ANCHOR = 2;

  let exportsP = null;
  let current = null; // { name, bytes }

  function loadModule() {
    if (!exportsP) {
      const bin = atob(B.wasm);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      exportsP = WebAssembly.instantiate(bytes, {}).then((r) => r.instance.exports);
    }
    return exportsP;
  }

  /** Run the Rust verifier. Mirrors the calling convention in crates/elc-wasm. */
  async function verifyBytes(certBytes, opts) {
    const e = await loadModule();
    const enc = new TextEncoder();
    const key = enc.encode((opts.key || "").trim());
    const p = e.elc_alloc(certBytes.length);
    new Uint8Array(e.memory.buffer, p, certBytes.length).set(certBytes);
    let kp = 0;
    if (key.length) {
      kp = e.elc_alloc(key.length);
      new Uint8Array(e.memory.buffer, kp, key.length).set(key);
    }
    const flags = (opts.strict ? FLAG_STRICT : 0) | (opts.anchor ? FLAG_ANCHOR : 0);
    const ots = opts.ots || new Uint8Array(0);
    let op = 0;
    if (ots.length) {
      op = e.elc_alloc(ots.length);
      new Uint8Array(e.memory.buffer, op, ots.length).set(ots);
    }
    const r = e.elc_verify(p, certBytes.length, flags, kp, key.length, op, ots.length);
    const len = new DataView(e.memory.buffer).getUint32(r, true);
    const json = new TextDecoder().decode(new Uint8Array(e.memory.buffer, r + 4, len).slice());
    e.elc_free(r, len + 4);
    e.elc_free(p, certBytes.length);
    if (kp) e.elc_free(kp, key.length);
    if (op) e.elc_free(op, ots.length);
    return JSON.parse(json);
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  let otsFile = null; // { name, bytes } for a kept, possibly upgraded, .ots

  function options() {
    return {
      strict: $("opt-strict").checked,
      anchor: $("opt-anchor").checked,
      key: $("opt-key").value,
      ots: otsFile ? otsFile.bytes : null,
    };
  }

  const SYMBOL = { pass: "✓", warn: "!", fail: "✗" };
  const VERDICT_CLASS = {
    valid: "verdict-valid",
    consistent_unsigned: "verdict-unsigned",
    invalid: "verdict-invalid",
  };
  const VERDICT_TITLE = {
    valid: "Valid",
    consistent_unsigned: "Consistent, but unsigned",
    invalid: "Invalid",
  };
  const VERDICT_MEANING = {
    valid:
      "Nothing covered by the signature has changed since it was signed. " +
      "Who signed it is only known if you checked the key against one you got elsewhere.",
    consistent_unsigned:
      "The file agrees with itself, but nothing in it says who made it. " +
      "Anyone can build a file like this from scratch.",
    invalid: "At least one check failed. Treat the file as altered or broken.",
  };

  function render(name, report) {
    const out = $("result");
    out.replaceChildren();
    out.hidden = false;

    if (report.error) {
      const box = el("div", "verdict verdict-invalid");
      box.append(el("p", "verdict-title", "Could not read this file"));
      box.append(el("p", "verdict-line", report.error));
      out.append(box);
      return;
    }

    const kind = report.verdict.kind;
    const box = el("div", "verdict " + VERDICT_CLASS[kind]);
    box.append(el("p", "verdict-title", VERDICT_TITLE[kind]));
    box.append(el("p", "verdict-meaning", VERDICT_MEANING[kind]));
    box.append(el("p", "verdict-line mono", report.verdict_line));
    out.append(box);

    const meta = el("dl", "meta");
    const row = (k, v, mono) => {
      meta.append(el("dt", null, k));
      meta.append(el("dd", mono ? "mono" : null, v));
    };
    row("File", name, true);
    row("Goal", report.goal || "(empty)");
    row("Session", report.session_id, true);
    row("Events", String(report.event_count));
    row("Started", report.started_at, true);
    row("Mode", report.mode === "strict" ? "Strict: requirements must be met" : "Inspection");
    out.append(meta);

    const list = el("ul", "checks");
    for (const c of report.checks) {
      const li = el("li", "check check-" + c.status);
      const sym = el("span", "check-sym", SYMBOL[c.status]);
      sym.setAttribute("aria-label", c.status === "pass" ? "passed" : c.status === "fail" ? "failed" : "note");
      li.append(sym);
      const body = el("div", "check-body");
      const line = el("p", "check-line");
      line.append(el("strong", null, c.title));
      line.append(document.createTextNode(c.detail));
      body.append(line);
      for (const n of c.notes) body.append(el("p", "check-note mono", n));
      li.append(body);
      list.append(li);
    }
    out.append(list);
  }

  async function run() {
    if (!current) return;
    $("status").textContent = "Verifying…";
    try {
      const report = await verifyBytes(current.bytes, options());
      render(current.name, report);
      $("status").textContent = "";
    } catch (err) {
      $("status").textContent = "The verifier could not run: " + err;
    }
  }

  function useBytes(name, bytes) {
    current = { name, bytes };
    $("current-file").textContent = name;
    run();
  }

  function useFile(file) {
    if (!file) return;
    file.arrayBuffer().then((buf) => useBytes(file.name, new Uint8Array(buf)));
  }

  function setupDrop() {
    const zone = $("drop");
    const input = $("file");
    input.addEventListener("change", () => useFile(input.files[0]));
    ["dragenter", "dragover"].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.add("drop-active");
      }),
    );
    ["dragleave", "drop"].forEach((ev) =>
      zone.addEventListener(ev, (e) => {
        e.preventDefault();
        zone.classList.remove("drop-active");
      }),
    );
    zone.addEventListener("drop", (e) => useFile(e.dataTransfer.files[0]));
  }

  function setupSamples() {
    const wrap = $("samples");
    for (const s of B.samples) {
      const b = el("button", "sample");
      b.type = "button";
      b.append(el("span", "sample-label", s.label));
      b.append(el("span", "sample-blurb", s.blurb));
      b.addEventListener("click", () => useBytes(s.file, new TextEncoder().encode(s.text)));
      wrap.append(b);
    }
  }

  function setupOptions() {
    ["opt-strict", "opt-anchor"].forEach((id) => $(id).addEventListener("change", run));
    $("opt-ots").addEventListener("change", async () => {
      const f = $("opt-ots").files[0];
      otsFile = f ? { name: f.name, bytes: new Uint8Array(await f.arrayBuffer()) } : null;
      $("opt-ots-clear").hidden = !otsFile;
      run();
    });
    $("opt-ots-clear").addEventListener("click", () => {
      otsFile = null;
      $("opt-ots").value = "";
      $("opt-ots-clear").hidden = true;
      run();
    });
    let t = null;
    $("opt-key").addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(run, 250);
    });
  }

  async function sha256hex(text) {
    const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function setupChallenge() {
    $("challenge-check").addEventListener("click", async () => {
      const out = $("challenge-result");
      // The README's canonical form: one line per file, "\n" separated, no
      // trailing newline. Forgive the usual copy-paste noise around it.
      const text = $("challenge-answer")
        .value.replace(/\r\n/g, "\n")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length)
        .join("\n");
      if (!window.crypto || !crypto.subtle) {
        out.textContent = "This browser has no SubtleCrypto here. Use: printf '%s' \"$(cat answer.txt)\" | shasum -a 256";
        return;
      }
      const h = await sha256hex(text);
      const ok = h === B.challengeAnswerSha256;
      out.className = "challenge-result " + (ok ? "ok" : "no");
      out.textContent = ok
        ? "Correct. Every file named, every tamper identified."
        : "Not yet. Hash " + h.slice(0, 16) + "… does not match. Check the order and the kind names.";
    });
  }

  function setupProvenance() {
    $("prov-crate").textContent = B.crate;
    $("prov-rustc").textContent = B.rustc;
    $("prov-sha").textContent = B.wasmSha256;
    $("prov-size").textContent = Math.round(B.wasmBytes / 1024) + " KB";
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!window.ELC_BUNDLE || typeof WebAssembly === "undefined") {
      $("status").textContent = "This browser cannot run the verifier (WebAssembly unavailable).";
      return;
    }
    setupDrop();
    setupSamples();
    setupOptions();
    setupChallenge();
    setupProvenance();
    loadModule().catch((e) => ($("status").textContent = "Could not load the verifier: " + e));
  });
})();
