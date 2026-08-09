# Ledgerly - bug bounty training lab

A self-hosted, realistic SaaS web app for practicing bug bounty hunting. The
entire lab is open every day: all vulnerability classes plus a compound chained
attack are live at once. You find each `FLAG{...}` on its surface, submit it to
bank the slot, report it, and a triage CLI accepts or rejects your reports.
Accepted issues feed the analytics dashboard.

## Vulnerability classes included

The lab implements the following classes as real, server-verified primitives.
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
| Chained attack | A compound surface that only unlocks when its factors combine. |

No class is named, hinted at, or advertised anywhere in the running UI - the
surfaces all present as ordinary product features.

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

- State lives in a named volume (`ledgerly-data`), so the lab survives
  container restarts. Delete the volume to start fresh: `docker compose down -v`.
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

| Command | What it does |
|---|---|
| `server.py run` | Start the lab |
| `server.py seed` | Print today's active classes (use `--verbose` for full context) |
| `server.py triage` | Review each pending report; `accept` / `reject` |
| `server.py flags` | List awarded flags |
| `server.py reset` | Re-seed today with a fresh draw (wipes today's state) |

## Capture flags

Every issue hides an opaque `FLAG{...}` on its surface. Submit a flag on the
**Flags** page to bank that slot. The flag string never says which class it
belongs to (slots are positional only). Any flag can be banked the moment its
string is found - no separate confirmation step. Capturing every flag, including
the compound chain flag, is what completes the day.

## How it works

1. Each calendar day produces a deterministic build with a tech fingerprint
   (server header, cookie name, API prefix, accent color). The product stays
   the same while the fingerprint changes daily.
2. You confirm a primitive server-side. The app records a class as exploited
   when the real exploit fires (each class is valid by construction).
3. You write a report. Reports are scored on completeness, class/severity
   accuracy, and reproducibility. A report only matches a class that was
   actually exploited.
4. Run `server.py triage`. Accepted reports validate the class and award a
   flag, written to history.
5. Bank each issue's `FLAG{...}` from the **Flags** page. When all flags are
   captured the day locks, and analytics shows your capability index,
   time-to-find per class, accuracy, and improvement tips against the repo's
   reference solve rates.

## Design rules

- **Every class exploitable every day.** The whole lab is open; there is no
  per-day subset.
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
    templates/  page templates
    static/     design system, confetti + per-class sounds
  data/lab.sqlite   runtime state (created on first run)
  reports/          submitted reports as JSON artifacts
  server.py    launcher + triage CLI
```
