# auto_login_shoonya

Automate the daily Shoonya (Finvasia) broker login for OpenAlgo, so the
`/api/v1/` REST API stays usable without you opening the web UI each
morning.

## Current flow (updated 2026-09 — post-OAuth edition)

Shoonya retired the vendor `QuickAuth` endpoint in its 2026 OAuth migration:
the legacy `/NorenWClientTP/` base answers 502 and `/NorenWClientAPI/QuickAuth`
rejects every vendor-code shape ("Invalid Vendor code"). There is also **no
token-renewal endpoint**. The only supported unattended re-login is the
headless browser OAuth flow, which is what this script now does:

1. Idempotency probe — decrypt the stored susertoken from OpenAlgo's DB and
   validate it against `/Limits`. Still valid → exit 0 (no-op).
2. Headless OAuth login — Playwright + Chromium opens
   `https://api.shoonya.com/OAuthlogin/investor-entry-level/login?api_key=<client_id>&route_to=<uid>`,
   fills `#lgnusrid` / `#lgnpwd` / `#lgnotp` (TOTP) and clicks LOGIN.
   Shoonya then delivers the single-use `code` **server-to-server** to the
   registered redirect URI (`https://vaibhavfury.duckdns.org/auth/shoonya/callback`)
   and only redirects the browser onward — so the script waits (event-driven)
   for the redirect to complete; if a `code=` is observed in the browser it
   also tries `GenAcsTok` itself, and otherwise falls back to the token
   OpenAlgo's callback just wrote into its DB. Either way the fresh token is
   validated against `/Limits` before anything is written.
3. Write + restart — `upsert_auth()` stores the new susertoken (Fernet,
   same key material), then the `openalgo` systemd service is **restarted**
   (not reloaded: `Type=simple` has no reload, and the Flask worker's
   `auth_cache` would otherwise serve the stale token until the 03:00 IST
   session-expiry TTL). Restart only happens after a real re-login, i.e.
   when the old token was already dead.

### Scheduling

Cron (system clock is UTC; `30 0 * * *` = 06:00 IST daily, no-op when the
session is still valid):

```
30 0 * * * /home/ubuntu/openalgo/.venv/bin/python /home/ubuntu/openalgo/auto_login_shoonya/auto_login_shoonya.py >> /home/ubuntu/openalgo/auto_login_shoonya/cron.log 2>&1
```

Every run POSTs its outcome to Telegram (`NOTIFICATION_WEBHOOK` /
`NOTIFICATION_CHAT_ID` in this script's `.env`, wired to the owner chat):
"still valid" (no-op), "re-logged in", or the failure reason.

Note: `SHOONYA_PASSWORD` must stay in this script's `.env` — the headless
OAuth login form is a real login and needs it. The idempotent probe path
works without it, but a re-login will fail without the password (and say so
on Telegram).

### Service

OpenAlgo runs as the `openalgo` systemd service (`/etc/systemd/system/openalgo.service`,
`ExecStart=/home/ubuntu/openalgo/.venv/bin/python app.py`). `app.py` was
patched with `allow_unsafe_werkzeug=True` (flask-socketio refuses Werkzeug in
production mode otherwise) — the same patch `algotradingdaily/scripts/install_openalgo_service.sh`
applies.

### End-to-end verification

Two optional checks run after a (re-)login — and the no-op probe — using
`OPENALGO_API_KEY` from this script's `.env`; both results land in the
Telegram status message:

1. `/api/v1/funds` — the token works through OpenAlgo's own API layer.
2. `/api/v1/quotes` for the NIFTY index (`NIFTY_SYMBOL` / `NIFTY_EXCHANGE`,
   default `NIFTY` / `NSE_INDEX`) — the session works on the market-data
   path; the Telegram message includes the LTP (last close when the market
   is shut).

If `/api/v1/funds` ever warns "Invalid openalgo apikey", re-generate at
`/apikey` in the OpenAlgo web UI and update the `.env`. Both checks are
cosmetic — the token itself is validated against Shoonya's `/Limits`
regardless.

### Requirements

```
pip install playwright pyotp python-dotenv   # in /home/ubuntu/openalgo/.venv
playwright install chromium && playwright install-deps chromium
```

(Selenium is NOT usable on this ARM64 VM: its bundled selenium-manager
binary is x86_64-only.)

---


## Findings (Phase 1)

Source code on disk (this OpenAlgo checkout) confirms:

1. **Broker login flow.** The web route is `GET/POST /<broker>/callback` in
   `blueprints/brlogin.py:37`. For Shoonya it has only **one** branch:
   the browser is first redirected to
   `https://api.shoonya.com/OAuthlogin/authorize/oauth?client_id=<id>` and
   the user authenticates there; Shoonya redirects back to the callback
   with a `?code=`, which `auth_function(code)` exchanges for a token at
   `https://api.shoonya.com/NorenWClientAPI/GenAcsTok`
   (`broker/shoonya/api/auth_api.py::authenticate_broker`, line 11).
   **There is no userid/password/TOTP path wired into OpenAlgo's Shoonya
   integration.** The classic Noren `QuickAuth` is not called from
   anywhere in the repo.
2. **Token storage.** The susertoken is stored encrypted with Fernet in
   the `auth` column of the `auth` table (`database/auth_db.py:179`, the
   `Auth` SQLAlchemy model). The encryption key is derived in
   `database/auth_db.py:86-95` from `API_KEY_PEPPER` + `FERNET_SALT`
   (PBKDF2, 100k iterations). The `Auth` row's `name` column is the
   **OpenAlgo** username, not the Shoonya userid; for Shoonya,
   `user_id` is NULL and the broker is `shoonya`. Verified against the
   live DB on this install: `name='vaibhav' broker='shoonya' user_id=None
   is_revoked=False`.
3. **Programmatic broker-login endpoint? — No.** The only broker
   authentication surface is `/<broker>/callback`, which (a) requires a
   logged-in Flask session and (b) requires a `?code=` from the OAuth
   flow. There is no documented or undocumented REST endpoint that
   accepts API-key auth and triggers a broker login. `/api/broker/credentials`
   only updates the `.env` file (`blueprints/broker_credentials.py:181`)
   and does not touch the broker session. `/auth/broker` is a session
   redirect, not a login trigger. `/_try_resume_broker_session` in
   `blueprints/auth.py:189` validates an *existing* token, it does not
   mint a new one.
4. **How `/api/v1/` consumes the token.** Every REST endpoint goes through
   `get_auth_token_broker(api_key)` (`database/auth_db.py:1004`), which
   reads the `Auth` row by `name` (= the OpenAlgo username resolved
   from the API key), decrypts `auth.auth` with the same Fernet, and
   returns the susertoken. The in-process `auth_cache` (TTLCache, TTL
   until next 03:00 IST session expiry) caches the resolved tuple by
   `sha256(api_key)` key. **The cache is checked before the DB;** once
   populated, only an explicit `auth_cache.clear()` (or a `is_revoked=True`
   re-check) refreshes it.
5. **Shoonya auth contract.** Successful Shoonya auth returns a
   `susertoken` (string), used as `Authorization: Bearer <susertoken>`
   against `https://api.shoonya.com/NorenWClientAPI/Limits` (see
   `broker/shoonya/api/funds.py:14`). The same endpoint is what
   `_try_resume_broker_session` uses to validate a stored token. The
   susertoken is stored in `auth.auth` (not `auth.feed_token` — Shoonya
   does not return a separate feed token).

## Decision (Phase 2)

| Option | Verdict | Why |
| --- | --- | --- |
| **A. Official programmatic path** | **Not available** | No REST endpoint accepts API-key auth and refreshes the broker session. The only login surface is the OAuth browser flow. |
| **B. Direct Shoonya `QuickAuth` + write to OpenAlgo DB** | **Chosen** | `QuickAuth` is the only Shoonya path that works with userid + password + TOTP and no browser. Writing through OpenAlgo's own `upsert_auth()` reuses its tested Fernet encryption, ZMQ cache-invalidation publish (for the out-of-process WS proxy), and multi-session teardown gate. There is already project precedent: `scripts/extract_broker_token.py` reads the same DB the same way. |
| **C. Call OpenAlgo's own login function internally** | **Not viable** | The Shoonya plugin's `authenticate_broker(code)` only accepts an OAuth `code`, which can only be obtained from a browser. |
| **D. Browser automation (Playwright)** | Rejected | Fragile, requires a headless Chromium, and the OAuth `code` callback is single-use. Strictly worse than B when B works. |

The single known risk of B: the in-process `auth_cache` in the long-running
gunicorn worker is keyed by `sha256(api_key)` and is checked before the DB,
so writing a new token alone is not enough — the worker keeps serving the
stale cached token. The script handles this by reloading the gunicorn
worker (`systemctl reload openalgo` or `SIGHUP` to a PID file) immediately
after `upsert_auth`, which forces a fresh import of the Auth row on the
next request.

## What it does

1. **Probe** the broker session already stored in OpenAlgo's `db/openalgo.db`.
   If Shoonya's `/Limits` endpoint accepts it, the script exits 0 immediately
   (idempotent no-op).
2. Otherwise, call Shoonya's `QuickAuth` (NorenWClientAPI) with your
   userid + SHA-256(password) + TOTP + vendor code, receiving a fresh
   `susertoken`.
3. **Validate** the new token against `/Limits` before writing it.
4. Write the new token through OpenAlgo's own `database.auth_db.upsert_auth`,
   so the Fernet encryption, the ZMQ cache-invalidation publish (for the
   out-of-process WebSocket proxy), and the multi-session teardown gate
   all use the project's tested code paths.
5. Reload the long-running gunicorn worker (`systemctl reload openalgo` or
   `SIGHUP` to a PID file) so the in-process `auth_cache` picks up the new
   token on the very next request. Without this, REST calls would keep
   serving the cached (stale) token for up to ~18 hours.
6. Optionally POST a notification to a webhook (Telegram / Slack / ntfy).

## What it does NOT do

- It does **not** modify any file inside the OpenAlgo checkout.
- It does **not** use OAuth. Shoonya's `QuickAuth` (the older Noren API
  accepting userid + password + TOTP directly) is the only path that
  works without a browser. If Finvasia deprecates it, fall back to the
  OpenAlgo web UI (the script is non-invasive and can be disabled
  without breaking anything).
- It does **not** implement the multi-device OAuth flow that the OpenAlgo
  web UI uses — that flow requires an interactive browser session to
  receive Shoonya's `?code=` callback. Use the web UI once if you ever
  need to enroll a new device.

## Setup

1. Copy `.env.example` to `.env` next to the script.
2. Fill in your Shoonya credentials and OpenAlgo details. The
   `OPENALGO_DIR` must point at the OpenAlgo checkout (so the script can
   read its `.env` and import `database.auth_db`).
3. The vendor code (`SHOONYA_VC`) defaults to `OA` (OpenAlgo). Confirm
   this with Finvasia support if you see `Invalid Vendor code` in the
   log — the OAuth `client_id` (the part after `:::` in
   `BROKER_API_KEY`) is a different field and is *not* the vendor code.
4. `SHOONYA_TOTP_SECRET` is the base32 secret you enrolled in Shoonya's
   2FA settings. `pyotp` normalises whitespace/padding, so the
   `JBSWY3DPEHPK3PXP`-style value shown in your authenticator's setup
   screen works directly.
5. Test the script manually before scheduling:
   ```bash
   uv run python auto_login_shoonya.py --check-only
   # → exit 0 with "Existing broker session is still valid" if today
   #   is a good day, or "Found Auth row..." + "proceeding with re-login"
   #   if the token is already stale.
   ```
6. Once confident, schedule it (see "Cron" below).

## Usage

```
uv run python auto_login_shoonya.py [options]

  --check-only    Probe the existing token; exit 0 if valid, 1 if not.
                  Never re-logs in. Useful as a daily health check.
  --force         Skip the idempotency probe and always run a new
                  QuickAuth. Use sparingly — most days the probe is
                  enough.
  --dry-run       Run QuickAuth + the /Limits probe, but do NOT write
                  the new token to OpenAlgo's DB and do NOT reload
                  gunicorn. Use to validate the credentials/secret/
                  vendor-code combo before going live.
  --script-dir DIR  Directory containing this script and its .env
                  (default: alongside the script).
```

### Exit codes

| Code | Meaning |
| ---: | --- |
| 0    | Success or no-op (existing session still valid, or new session written and verified) |
| 1    | Generic failure |
| 2    | Configuration error (missing env, wrong OpenAlgo .env, etc.) |
| 3    | Shoonya auth failure (bad password, wrong TOTP, invalid vendor code, etc.) |
| 4    | Network / broker unavailable after all retries |

## Cron

The OpenAlgo repo's `install.sh` registers a systemd service called
`openalgo` (eventlet single worker). Pair that with a daily cron line:

```cron
# 30 8 * * 1-5 = 08:30 IST, Mon-Fri
30 8 * * 1-5  cd /home/ubuntu/openalgo/auto_login_shoonya && /home/ubuntu/openalgo/.venv/bin/python auto_login_shoonya.py >> auto_login_cron.log 2>&1
```

IST is UTC+5:30, so the equivalent in UTC is `30 3 * * 1-5`. The local
cron daemon on the VPS uses the server's local time, which is normally
IST for India-located VPSes — double-check with `date`.

For a separate health-check cron (does not re-login, just probes):
```cron
# every 30 minutes during market hours (09:00 - 15:30 IST)
*/30 9-15 * * 1-5  cd /home/ubuntu/openalgo/auto_login_shoonya && /home/ubuntu/openalgo/.venv/bin/python auto_login_shoonya.py --check-only >> auto_login_health.log 2>&1 || /path/to/alert-script.sh
```

## How to verify after the cron fires

The script logs to `auto_login.log` and to stdout. To verify the new
token is in place:

```bash
uv run --project /home/ubuntu/openalgo python /home/ubuntu/openalgo/scripts/extract_broker_token.py
# prints the current Shoonya susertoken (decrypted from the Auth row)
```

To verify the running Flask worker actually serves it:

```bash
curl -s -X POST http://127.0.0.1:5000/api/v1/funds \
  -H "Content-Type: application/json" \
  -d '{"apikey":"'$OPENALGO_API_KEY'"}'
```

If the `auth_cache` is stale (script ran but the curl still gets 401),
a second `systemctl reload openalgo` is enough — `auto_login.log` will
warn if the optional end-to-end probe failed.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Config error: Missing required Shoonya credentials` | `.env` not filled in or has wrong keys | Edit `.env`; copy from `.env.example` |
| `Config error: OpenAlgo .env is missing required keys: ...` | The OpenAlgo instance's `.env` doesn't have `BROKER_API_KEY` / `BROKER_API_SECRET` / `API_KEY_PEPPER` / `FERNET_SALT` | Run the OpenAlgo app once via `uv run app.py` so `utils/env_check.py` auto-provisions the salt; check `OPENALGO_DIR` is right |
| `No shoonya Auth row in OpenAlgo DB` | The script has never seen a shoonya login | Log in to OpenAlgo's web UI once so the row is created; re-run |
| `Invalid Vendor code` from Shoonya | `SHOONYA_VC` is wrong | The script defaults to `<your userid>_U` (per the Shoonya FAQ rule: "The vendor code will be your Client Code_U For Examples FA12345_U"). If your account uses a different value, set `SHOONYA_VC=` explicitly in `.env` |
| `Invalid password` / `Invalid TOTP` | Wrong `SHOONYA_PASSWORD` or `SHOONYA_TOTP_SECRET` | Re-check; TOTP secret is the base32 value from your authenticator app's 2FA setup screen |
| `Clock drift of ~Ns detected` | VPS clock is out of sync | Enable systemd-timesyncd (`timedatectl set-ntp true`) or chrony |
| `--check-only` exits 0 but `/api/v1/` still 401s | `auth_cache` is stale; the script wrote the new token but the running gunicorn worker keeps the cached one | The script's `OPENALGO_RELOAD_MODE=systemd` should have already recycled the worker. If `sudo systemctl reload openalgo` failed silently, run it manually |
| 401 errors stop 5-15 minutes after cron | gunicorn worker was recycled but WebSocket adapters still hold the old token | The cache invalidation publish on `upsert_auth` should propagate to the WS proxy and force reconnect. If not, `systemctl restart openalgo` (full restart, not reload) |
| The script keeps re-logging in every day despite the session being valid | The OpenAlgo worker is recycling daily for some other reason, and the cron runs *before* the rollover completes | Move the cron to 08:30 IST or later; the broker rollover is around 03:00 IST and the new token is usually valid by 06:00 |

## Security notes

- The script writes the new susertoken to `db/openalgo.db` encrypted with
  the same Fernet key OpenAlgo uses. It does not print the token. It does
  not log the full QuickAuth response.
- The script reads `BROKER_API_SECRET` from OpenAlgo's `.env`. Treat
  that file like any other credential store.
- `auto_login.log` does **not** contain credentials. It does contain
  the OpenAlgo username and the Shoonya userid, both of which are
  already in `.env` and `BROKER_API_KEY`.
- `.env` is gitignored (the OpenAlgo repo's top-level `.gitignore`
  covers `*.env` patterns; the file is not in the auto_login_shoonya/
  directory's gitignore because the directory is currently outside any
  VCS — add your own `.gitignore` line `auto_login_shoonya/.env` if you
  copy the directory into a project repo).
