# Ledgerly - bug bounty training lab

A self-hosted, realistic SaaS web app for practicing bug bounty hunting. The
**entire lab is open every day**: all 24 vulnerability classes plus the
compound chain (25 flags) are live at once. You find each `FLAG{...}` on its
surface, submit it to bank the slot, report it, and a triage CLI accepts or
rejects your reports. Accepted issues feed the analytics dashboard.

## Vulnerability classes included

The lab implements all of the following as real, server-verified primitives.
Every class is exploitable every day.

| Class | Short description |
|---|---|
| SQL injection | An authentication query assembled from raw user input. |
| NoSQL injection | A JSON filter accepted verbatim, including query operators. |
| IDOR | Reading an object by a guessed identifier with no ownership check. |
| Server-side template injection | User text rendered as a template. |
| Server-side request forgery | An outbound fetch driven by a user-supplied URL. |
| Mass assignment | A request body merged into an object beyond the intended fields. |
| Business logic flaw | Negative or zero values accepted in a financial flow. |
| Cross-site scripting | Stored user content served back without escaping. |
| CSRF | A state change that never verifies who is asking. |
| CORS misconfiguration | A reflected origin allowed to read responses with credentials. |
| Open redirect | An unvalidated redirect target. |
| Clickjacking | A sensitive page that can be framed. |
| JWT weakness | Signed tokens accepted without a valid signature. |
| OAuth flow flaw | A partner sign-in that skips a required handshake step. |
| Insecure deserialization | An untrusted blob reconstructed into arbitrary objects. |
| Path traversal | A filename used to open a file without sanitization. |
| Command injection | User input reaching a shell command. |
| XML external entity | External entities expanded from user-supplied XML. |
| Race condition | A check-then-act path with no lock. |
| ReDoS | A user-controlled regular expression run against input. |
| Sensitive info disclosure | Runtime configuration exposed by a status endpoint. |
| GraphQL flaw | A GraphQL layer with authorization off. |
| Prototype pollution | A JSON merge that walks reserved prototype keys. |
| Token lifecycle gap | Rotated credentials that keep working. |
| Chained attack | A compound surface that only unlocks when every chain primitive combines. |

No class is named, hinted at, or advertised anywhere in the running UI - the
surfaces all present as ordinary product features.

## Pre-built attack chains

Each day also designates one of seven pre-built chains (2-4 primitives each)
from the chain engine. The chain surface presents as a normal product page; the
recovery surface unlocks when every factor output is presented together.

| Chain | Primitives |
|---|---|
| forge_read | JWT weakness + IDOR |
| hook_leak | SSRF + info disclosure |
| cross_write_exec | CSRF + XSS + prototype pollution |
| redirect_token | Open redirect + OAuth flaw + token lifecycle |
| price_race | Business logic + race condition + mass assignment |
| xml_shell | XXE + command injection + path traversal |
| server_hold | SQLi + deserialization + SSTI + JWT |

## Run it

```bash
python3 server.py run            # http://0.0.0.0:5001 (all interfaces)
python3 server.py run --port 9000
python3 server.py run --host 127.0.0.1   # localhost only (no proxy routing)
```

Demo login: `hunter` / `hunter-pass`. Or register your own account.

## Run with Docker

Each player runs their own instance on their own machine.

```bash
docker compose up --build        # http://localhost:5001
```

Without compose:

```bash
docker build -t ledgerly-lab .
docker run --rm -p 5001:5001 ledgerly-lab
```

Notes:

- State lives in a named volume (`ledgerly-data`), so a day survives container
  restarts. Delete the volume to start a fresh day: `docker compose down -v`.
- The day is deterministic from the container clock, so every player gets the
  same fully-open lab each day.
- To reach it from Burp Suite, publish the port and browse to the host machine's
  LAN IP, not `localhost` (see below).
- Add `-p 127.0.0.1:5001:5001` instead of `-p 5001:5001` if you want the lab
  reachable only from the host machine.

### Intercepting with Burp Suite

The lab binds `0.0.0.0` so it is reachable through a proxy. To see every
request in Burp:

1. Start Burp (Proxy > Intercept on, listener on `127.0.0.1:8080`).
2. Point your browser at Burp's proxy (e.g. FoxyProxy, or Burp's embedded
   browser, which is pre-wired).
3. Browse to the lab via its **LAN IP**, never `localhost` - browsers bypass
   the proxy for loopback, so `localhost` traffic would miss Burp. The server
   prints the exact URL to use at startup (e.g. `http://192.168.1.20:5001`).
   Find it anytime with `hostname -I`.

Anything not needed by the lab is ordinary HTTP - no TLS, no certificate
setup. The webhook test endpoint (`POST .../webhooks/test`) performs the
server-side request in the background; you'll see only the response, and the
SSRF primitive is confirmed with an out-of-band callback.

| Command | What it does |
|---|---|
| `server.py run` | Start the lab |
| `server.py seed` | Print today's active classes (use `--verbose` for full context) |
| `server.py triage` | Review each pending report; `accept` / `reject` |
| `server.py flags` | List awarded flags |
| `server.py reset` | Re-seed today with a fresh draw (wipes today's state) |

## Capture flags

Every active issue hides an opaque `FLAG{...}` on its surface - the same place
the issue's data flows, so finding it is your proof the primitive is real:

Submit a flag on the **Flags** page to bank that slot. The flag string itself
never says which class it belongs to (slots are positional only). Any flag from
today's build can be banked the moment its string is found - no separate
confirmation step. Capturing all of today's flags (the chain primitives plus
the chain flag) is what completes the day.

## How a day works

1. Each calendar day + reset counter produces a deterministic seed.
2. The seed designates the compound chain (which 2-4 primitives the recovery
   surface requires) plus a tech fingerprint (Flask, Express, Django, Rails,
   FastAPI: server header, cookie name, API prefix, accent color). UI and
   headers change; the product stays the same. All 25 flags are open every day.
3. You confirm a primitive server-side. The app records a class as exploited
   when the real exploit fires (each class is valid by construction, and only
   the drawn classes are exploitable).
4. You write a report. Reports are scored on completeness, class/severity
   accuracy, and reproducibility. A report only matches a class that was
   actually exploited.
5. Run `server.py triage`. Accepted reports validate the class and award a
   flag, written to history.
6. Bank each issue's `FLAG{...}` from the **Flags** page (anytime, once found).
   When all of today's flags - the chain primitives plus the chain flag - are
   captured the day locks (confetti + a capture sound), and analytics shows
   your capability index, time-to-find per class, accuracy, and improvement
   tips against the repo's reference solve rates.

## Design rules

- **Every class exploitable every day.** The whole 25-flag lab is open;
  there is no per-day subset.
- **Never untriaged.** Triage can only accept a report whose class was
  confirmed exploited by the server.
- **The UI does not leak answers.** Surfaces exist, but nothing says what is
  wrong with them. Hints, example payloads, and the active class list are never
  rendered; analytics only shows rows for classes you have already touched.
- **Fingerprints change daily.** Server header, cookie name, API prefix, and
  accent hue follow the drawn tech stack, so each day reads as a different
  deployment.

## Layout

```
labs/ledgerly/
  ledgerly/
    config.py   day seed, tech fingerprints, feature toggles, secrets
    store.py    sqlite persistence (day, vulns, reports, flags, history)
    vulns.py    class registry, report scoring, analytics
    web.py      Flask routes and the vulnerable sinks
    templates/  31 page templates
    static/     design system, confetti + per-class sounds
  data/lab.sqlite   runtime state (created on first run)
  reports/          submitted reports as JSON artifacts
  server.py    launcher + triage CLI
```
