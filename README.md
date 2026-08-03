# Ledgerly - bug bounty training lab

A self-hosted, realistic SaaS web app for practicing bug bounty hunting. Every
day Ledgerly draws **exactly 3 vulnerability classes** from a pool of 7 and
seeds them into a deterministic per-day build. You find them, exploit them,
report them, and a triage CLI accepts or rejects your reports. Accepted issues
earn flags and feed the analytics dashboard.

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
- The day draw is deterministic from the container clock, so every player gets
  their own per-day draw with the same 3 classes seeded that day.
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
the issue's data flows, so you only see it once the primitive is real:

| Class | Where the flag is revealed |
|---|---|
| `sqli` | Admin page, after the auth bypass lands you in as admin |
| `idor` | Second line item on a foreign invoice (`INV-1006`) |
| `ssti` | Preview response via `{{flag}}` in the template |
| `ssrf` | `/internal/secret` response when the webhook test reaches it |
| `mass_assignment` | Team page, after `role` escalates to admin |
| `logic` | The invoice you created with a negative line total |
| `nosqli` | The private client row leaked by a filter operator |

Submit a flag on the **Flags** page to bank that slot. The flag string itself
never says which class it belongs to (slots are positional only), and it only
banks if the server has already recorded that class as exploited - pasting a
flag for a class you haven't confirmed gets rejected. Capturing all of the
day's flags is what completes the day.

## How a day works

1. Each calendar day + reset counter produces a deterministic seed.
2. The seed draws 3 classes from the pool and a tech fingerprint (Flask,
   Express, Django, Rails, FastAPI: server header, cookie name, API prefix,
   accent color) plus feature toggles. UI and headers change; the product stays
   the same.
3. You confirm a primitive server-side. The app only records a class as
   exploited when the real exploit fires (each class is valid by construction,
   and only the drawn classes are exploitable).
4. You write a report. Reports are scored on completeness, class/severity
   accuracy, and reproducibility. A report only matches a class that was
   actually exploited.
5. Run `server.py triage`. Accepted reports validate the class and award a
   flag, written to history.
6. Bank each issue's `FLAG{...}` from the **Flags** page. When all of today's
   flags are captured the day locks (confetti + a capture sound), and analytics
   shows your capability index, time-to-find per class, accuracy, and
   improvement tips against the repo's reference solve rates.

## Vulnerability pool

| Class | Surface | Why it's server-verified |
|---|---|---|
| `sqli` | Sign in | Auth query built from raw input; a comment terminator cancels the password clause |
| `idor` | Invoice detail (+ API) | Object id taken from the path with no ownership check |
| `ssti` | Notification preview | Editor input rendered as a Jinja template server-side |
| `ssrf` | Webhook test | Outbound fetch driven by user URL, including loopback |
| `mass_assignment` | Team settings API | Request body merged into the user object; `role` is writable |
| `logic` | Invoice lines | Negative quantity / unit price accepted into the total |
| `nosqli` | Client list filter | JSON filter operators accepted verbatim, leaking private clients |

When a class is not drawn, its sink is inert (parameterized, rejected, hidden,
or 404). `/internal/secret` only exists on SSRF days. Only the three drawn
classes can ever be exploited, so the day is never gated on a false positive.

## Design rules

- **Only 3 exploitable classes per day.** Verified per-draw: with a class
  absent, its exploit is inert.
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
    templates/  20 page templates
    static/     design system, confetti + per-class sounds
  data/lab.sqlite   runtime state (created on first run)
  reports/          submitted reports as JSON artifacts
  server.py    launcher + triage CLI
```

Secrets worth knowing: `admin` has a random per-day password (find it or bypass
it), and `/internal/secret` is the SSRF target (its token is the `ssrf` flag).
Both are deterministic from the day's seed.
