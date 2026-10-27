# Adding a target — the wizard (no jargon)

You don't need to know anything about APIs. Open the local UI and paste what you
have; the tool figures out the rest.

```bash
provenance-probe serve          # then open http://127.0.0.1:8770/wizard
```

The architecture and math behind all of this is in
[ARCHITECTURE.md](ARCHITECTURE.md); this page is just how to use it.

---

## One box, three kinds of input

The "Add a target" page has a single box. Paste **any** of these:

### 1. An API address (a plain URL)

Example: `https://api.openai.com/v1` or `https://api.deepseek.com`.

- The tool asks your permission before sending anything (a short identify test —
  a few small requests; a full provenance check is ~28 requests total).
- It then figures out on its own whether the service speaks the OpenAI or
  Anthropic dialect — **you never pick an "API style".**
- If it recognizes the vendor (OpenAI, Anthropic, DeepSeek, Moonshot, OpenRouter,
  Gemini) and you already have that vendor's key in your environment
  (`OPENAI_API_KEY`, etc.), it offers to use it. The key value is **never written
  to the saved config** — only its environment-variable name is.
- If it's confident, it fills in the target. If it's unsure, it asks you to
  confirm rather than guessing.

### 2. A `curl` command (for a logged-in web app)

Some services are web apps, not APIs — you sign in and chat in a browser. For
those, capture one request:

1. Sign in to the app in your browser.
2. Open DevTools → Network (F12, or ⌘⌥I on a Mac).
3. Send one short message like "fingerprint me".
4. Find the request that fires when you hit send (usually a POST named chat /
   completion / message / conversation), right-click → Copy → **Copy as cURL**.
5. Paste it into the box, and put the exact message ("fingerprint me") in the
   message field so the tool can find it.

Never captured a request before? The wizard links to a **step-by-step guide**
tailored to your browser, or run:

```bash
provenance-probe capture https://chat.the-app.com          # prints the steps
```

### 3. A HAR file

Prefer a file? In DevTools → Network, right-click → **Save all as HAR**, and paste
the file's contents. A HAR also captures the response, so the tool can auto-fill
where the reply and token counts live.

---

## What happens when you save

The wizard runs a quick 2-probe **dry-run** before saving, to make sure replaying
the request is safe (it won't spam your real chat or fail).

A signed app (a new signature on every request) or a chat that remembers earlier
messages can reject that replay. The tool does not pretend the replay worked, and
it does not confirm a model switch from what the model calls itself. A switch can
still be flagged by a fresh check — the tokenizer measurement, or the shape of
the API response — and the verdict says the replay was impossible and which of
those two signals carried it. If neither was measured, the verdict is not a clean
bill.

Then:

- The target config is written to `targets.json` (safe to commit — no secrets).
- If the request had a session cookie, it's written to `.env.capture`, which is
  **gitignored and owner-only (0600)** — run `source .env.capture` before
  probing, or set it as a CI secret. It is **never** put in the committed config.

Then click **"Probe it now"** — it hands off to the probe tool with everything
filled in, and you get a plain-language verdict: *"this service is served by a
Chinese-origin model"* (or not), with the technical evidence a click away.

---

## Automated capture (optional)

If you'd rather not use DevTools, install the optional capture extra and let the
tool drive a browser:

```bash
pip install -e '.[capture]' && playwright install chromium
provenance-probe capture https://chat.the-app.com --auto --i-am-authorized
```

It opens a browser. **You log in first** (the tool never sees your password and
does not record the login), then send one message; it captures the request to a
private, owner-only HAR file and tells you to paste it into the wizard. Only use
this on services you're authorized to test.

---

## Using a local OmniRoute router (optional)

If you run [OmniRoute](https://github.com/diegosouzapw/OmniRoute) locally, you can
pick a model from its catalog and probe through it — zero typing:

```bash
provenance-probe omniroute --list                          # see routes
provenance-probe omniroute --route oc/deepseek-v4-flash-free \
    --expect-ref DeepSeek-V3 --i-am-authorized
```

Because OmniRoute injects a large hidden prompt, measuring *through* it is only
fully trusted once a **calibration** step confirms that injection cancels cleanly
for your OmniRoute version. Until then the verdict is honestly labeled
**SUGGESTIVE** rather than CONFIRMED, and the tool cross-checks the router's
claimed model against the fingerprint (agreeing = corroborated; disagreeing =
held for human review, never auto-published). See
[ARCHITECTURE.md §6](ARCHITECTURE.md#6-omniroute-integration-optional-accelerator--second-evidence-source).

---

## Scope & authorization

Only run against systems you are **authorized in writing** to test. Targets carry
an `authorized` flag; active probing and browser-driving abort without it. The
behavioral probes send politically sensitive prompts — put that in your test
authorization explicitly.
