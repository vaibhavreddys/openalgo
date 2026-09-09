"""Auto-refresh the Shoonya (Finvasia) broker session inside OpenAlgo.

This script eliminates the daily manual broker login that OpenAlgo's web UI
requires. It runs out of cron (e.g. 08:30 IST on weekdays) and is fully
idempotent: if the stored broker token is still valid, it does nothing and
exits 0.

Flow (post-OAuth edition — see README.md):

    1. Load credentials from THIS script's .env (Shoonya password + TOTP
       secret). Load the OpenAlgo instance's .env (API_KEY_PEPPER, FERNET_SALT,
       BROKER_API_KEY, BROKER_API_SECRET) to gain access to the same Fernet
       key OpenAlgo uses to encrypt the Auth row.
    2. Open the OpenAlgo SQLite DB read-only first, decrypt the current
       susertoken, probe Shoonya /Limits with it. If it succeeds, exit 0
       (no-op, the session is still good).
    3. Otherwise run a HEADLESS OAUTH LOGIN: drive Shoonya's hosted login
       page (Playwright + Chromium) with userid/password/TOTP. The page
       is a Vue SPA that performs two XHRs in-page — QuickAuth (returns
       the susertoken) and GetAuthCode (returns the OAuth authorization
       ``code``) — instead of redirecting to the app callback. The script
       intercepts both JSON responses and extracts the code. Exchange the
       code via GenAcsTok for the OpenAlgo-compatible access token.
    4. Probe /Limits with the new token to confirm it works before writing
       anything to disk. If GenAcsTok loses the single-use ``code`` to
       OpenAlgo's own callback (the browser redirect also reaches the
       OpenAlgo server, which consumes the code itself), fall back to the
       freshly-written DB token instead.
    5. Write the new susertoken through OpenAlgo's own `upsert_auth()` so the
       Fernet encryption, ZMQ cache invalidation, WS proxy pool cleanup and
       order-update adapter restart all use the project's tested code paths.
    6. Reload the gunicorn worker (systemctl reload / SIGHUP) so the
       in-process auth_cache in the long-running Flask worker picks up the
       new token on the very next request.
    7. POST a notification to the configured webhook (no-op if blank).

The script does NOT modify any file inside the OpenAlgo checkout. It only
reads .env and writes one row in db/openalgo.db (the encrypted Auth.auth
column). It assumes the broker is Shoonya; for any other broker the script
aborts with a clear error.

Requirements: `pip install playwright pyotp python-dotenv` inside the
OpenAlgo venv plus `playwright install chromium` (system deps via
`playwright install-deps chromium`).

Exit codes:
    0  success or no-op (token already valid, or new token written & verified)
    1  generic failure
    2  configuration error (missing env, wrong OpenAlgo .env, etc.)
    3  Shoonya auth failure (bad password, wrong TOTP, etc.)
    4  network / broker unavailable after all retries
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import parse_qs, urlsplit

try:
    from dotenv import load_dotenv
except ImportError:
    print(
        "FATAL: python-dotenv is required. Install with: uv pip install python-dotenv",
        file=sys.stderr,
    )
    sys.exit(2)

try:
    import pyotp
except ImportError:
    print("FATAL: pyotp is required. Install with: uv pip install pyotp", file=sys.stderr)
    sys.exit(2)

# Exit codes
EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_CONFIG = 2
EXIT_AUTH = 3
EXIT_NETWORK = 4

SHOONYA_BASE = "https://api.shoonya.com/NorenWClientAPI"
# Hosted login page for OAuth apps. ``api_key`` is the OAuth client_id and
# ``route_to`` the trading user id; the page pre-selects the app so a
# headless fill of the three fields (id/password/TOTP) is enough.
SHOONYA_OAUTH_LOGIN_URL = (
    "https://api.shoonya.com/OAuthlogin/investor-entry-level/login"
)
CLOCK_DRIFT_SECONDS = 30  # TOTP is time-based; warn if clock skew > 30s

log = logging.getLogger("auto_login_shoonya")


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #


def setup_logging(log_file: str | None) -> None:
    """Configure the auto_login_shoonya logger.

    Note: do NOT use logging.basicConfig() — by the time this is called, we
    may have already imported OpenAlgo's `database.auth_db`, which configures
    the root logger with its own handlers + a SensitiveDataFilter that
    stringifies every log argument (turning int %d into a TypeError, leaving
    the %-placeholders unformatted in the final output). See
    `utils/logging.py::SensitiveDataFilter.filter` and the bug comment in
    `ColoredFormatter.format` for the upstream details.

    Instead, attach a dedicated handler to our own `auto_login_shoonya`
    logger so our messages bypass OpenAlgo's filter chain.
    """
    fmt = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
    formatter = logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")

    # Drop any handler we may have inherited from OpenAlgo on this logger.
    for handler in list(log.handlers):
        log.removeHandler(handler)
    # Make sure log records we emit (and only ours) propagate to our handler.
    log.setLevel(logging.INFO)
    log.propagate = False  # do NOT bubble up to OpenAlgo's root handlers

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    log.addHandler(stream_handler)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            log.addHandler(file_handler)
        except OSError as exc:
            log.warning("Could not open log file %s: %s", exc)


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


class ConfigError(RuntimeError):
    pass


def load_config(script_dir: Path) -> dict[str, str]:
    """Load and validate configuration from the script's own .env.

    The OpenAlgo instance's .env is loaded separately in `import_openalgo_db`
    because we need its values to be present BEFORE importing database.auth_db.
    """
    env_path = script_dir / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=False)
    else:
        log.warning("No .env found at %s — relying on already-exported env vars", env_path)

    cfg = {
        "shoonya_user_id": os.getenv("SHOONYA_USER_ID", "").strip(),
        "shoonya_password": os.getenv("SHOONYA_PASSWORD", "").strip(),
        "shoonya_totp_secret": os.getenv("SHOONYA_TOTP_SECRET", "").strip(),
        "shoonya_imei": os.getenv("SHOONYA_IMEI", "openalgo_auto_login").strip(),
        "openalgo_dir": os.getenv("OPENALGO_DIR", "/home/ubuntu/openalgo").strip(),
        "reload_mode": os.getenv("OPENALGO_RELOAD_MODE", "systemd").strip().lower(),
        "pidfile": os.getenv("OPENALGO_GUNICORN_PIDFILE", "").strip(),
        "openalgo_api_key": os.getenv("OPENALGO_API_KEY", "").strip(),
        "notification_webhook": os.getenv("NOTIFICATION_WEBHOOK", "").strip(),
        "notification_chat_id": os.getenv("NOTIFICATION_CHAT_ID", "").strip(),
        "retry_max": int(os.getenv("RETRY_MAX_ATTEMPTS", "3")),
        "retry_base_delay": float(os.getenv("RETRY_BASE_DELAY", "5")),
        "login_timeout_seconds": float(os.getenv("LOGIN_TIMEOUT_SECONDS", "150")),
        "nifty_symbol": os.getenv("NIFTY_SYMBOL", "NIFTY"),
        "nifty_exchange": os.getenv("NIFTY_EXCHANGE", "NSE_INDEX"),
        "log_file": os.getenv("LOG_FILE", "auto_login.log").strip(),
    }

    # The plaintext password is required only when a real headless OAuth
    # login is performed (the hosted form needs it); the idempotent probe
    # path works without it. Enforced in perform_login_and_validate().
    missing = [k for k in ("shoonya_user_id", "shoonya_totp_secret") if not cfg[k]]
    if missing:
        raise ConfigError("Missing required Shoonya credentials in .env: " + ", ".join(missing))

    openalgo_path = Path(cfg["openalgo_dir"])
    if not openalgo_path.is_dir():
        raise ConfigError(f"OPENALGO_DIR does not exist: {openalgo_path}")
    if not (openalgo_path / ".env").is_file():
        raise ConfigError(f"OpenAlgo .env not found at {openalgo_path / '.env'}")
    if cfg["reload_mode"] not in ("systemd", "pidfile", "none"):
        raise ConfigError(
            f"OPENALGO_RELOAD_MODE must be 'systemd', 'pidfile' or 'none' (got {cfg['reload_mode']!r})"
        )
    if cfg["reload_mode"] == "pidfile" and not cfg["pidfile"]:
        raise ConfigError(f"OPENALGO_RELOAD_MODE=pidfile requires OPENALGO_GUNICORN_PIDFILE")

    return cfg


# --------------------------------------------------------------------------- #
# Shoonya HTTP helpers
# --------------------------------------------------------------------------- #


def _post_jdata(url: str, payload: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    """POST a NorenWClientAPI endpoint with the jData= form encoding."""
    body = "jData=" + json.dumps(payload)
    req = urllib_request.Request(
        url,
        data=body.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        raise RuntimeError(f"HTTP {exc.code} from {url}: {body_text or exc.reason}") from exc
    except urllib_error.URLError as exc:
        raise RuntimeError(f"Network error contacting {url}: {exc.reason}") from exc


def check_totp_clock(totp: pyotp.TOTP) -> None:
    """Warn (do not abort) if the system clock disagrees with the TOTP time
    step by more than CLOCK_DRIFT_SECONDS. TOTP is time-based; a drifted
    system clock will always produce an invalid factor2."""
    now_ts = int(time.time())
    now_dt = datetime.fromtimestamp(now_ts)
    totp_time = totp.timecode(for_time=now_dt) * totp.interval
    drift = abs(now_ts - totp_time)
    if drift > CLOCK_DRIFT_SECONDS:
        log.warning(
            "Clock drift of ~%ds detected between system time and TOTP timecode. "
            "Shoonya may reject the factor2 OTP. Consider running `chronyc tracking` "
            "or `ntpq -p` to verify NTP sync.",
            drift,
        )
    else:
        log.debug("TOTP clock OK (drift ~%ds)", drift)


# --------------------------------------------------------------------------- #
# Shoonya headless OAuth login (Playwright)
# --------------------------------------------------------------------------- #


def shoonya_oauth_code(
    client_id: str,
    user_id: str,
    password: str,
    totp_secret: str,
    timeout_seconds: float = 60.0,
    redirect_host: str = "",
) -> str | None:
    """Run the OAuth login page headlessly; return the authorization code.

    Shoonya's hosted OAuth login page is a Vue SPA: the form submit fires
    two in-page XHRs (QuickAuth, then GetAuthCode). GetAuthCode answers
    302 with a ``Location`` pointing at the app's registered OAuth callback
    (``https://<host>/shoonya/callback?code=...``), and the browser then
    navigates there. Reading XHR response bodies via Playwright is not
    reliable (the QuickAuth body is frequently unreadable), so this works
    at the request level instead:

      * a ``request`` listener records the callback URL — the single-use
        ``code`` is in its query string — the moment the browser asks for
        it; and
      * the callback request is ABORTED via routing. The headless browser
        has no OpenAlgo web session, so the callback would bounce to the
        login page and waste the single-use code; aborting keeps the code
        ours to exchange via GenAcsTok.

    The QuickAuth verdict is read from the page state when possible and
    otherwise inferred from navigation: if the browser heads for the
    callback URL, the credentials were accepted.

    Raises RuntimeError (retryable) when the flow stalls or the gateway
    5xxes; the caller classifies credential errors as fatal.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "playwright is not installed in this venv. Run "
            "`pip install playwright && playwright install chromium`."
        ) from exc

    totp = pyotp.TOTP(totp_secret)
    check_totp_clock(totp)

    captured: dict[str, Any] = {}

    def _on_request(request: Any) -> None:
        url = getattr(request, "url", "") or ""
        if "/callback" in url and "code=" in url and "code" not in captured:
            captured["code"] = url
        if "/NorenWClientAPI/QuickAuth" in url and "qa" not in captured:
            # Headers of XHR *requests* are readable even when response
            # bodies are not; the response listener below adds the verdict.
            captured["qa"] = {"at": time.time()}

    def _on_response(response: Any) -> None:
        try:
            url = getattr(response, "url", "") or ""
        except Exception:
            return
        if "/NorenWClientAPI/QuickAuth" in url and response.status >= 500:
            # Gateway 5xx (the 06:00 IST blip) — retryable by the caller.
            raise RuntimeError(
                f"Shoonya QuickAuth gateway error HTTP {response.status} — "
                "transient; retrying"
            )

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        try:
            page = browser.new_page()
            page.on("request", _on_request)
            page.on("response", _on_response)
            # Abort the OAuth callback navigation: without a web session it
            # can only waste the single-use code. (It also keeps the final
            # page on Shoonya's domain, which makes error text readable.)
            callback_host = redirect_host or urlsplit(_read_env_value(
                Path(__file__).resolve().parents[2] / ".env", "HOST_SERVER") or ""
            ).netloc
            if callback_host:
                page.route(
                    f"https://{callback_host}/*callback*",
                    lambda route: route.abort(),
                )

            login_url = f"{SHOONYA_OAUTH_LOGIN_URL}?api_key={client_id}&route_to={user_id}"
            log.info("Opening Shoonya OAuth login page for %s ...", user_id)
            page.goto(login_url, wait_until="networkidle", timeout=45_000)

            page.fill("#lgnusrid", user_id)
            page.fill("#lgnpwd", password)
            # Generate the OTP as late as possible so it cannot lapse while
            # the form is being submitted.
            page.fill("#lgnotp", totp.now())
            page.click("button:has-text('LOGIN')")

            deadline_ms = int(timeout_seconds * 1000)
            waited_ms = 0
            while "code" not in captured and waited_ms < deadline_ms:
                page.wait_for_timeout(500)
                waited_ms += 500

            if "code" in captured:
                query = parse_qs(urlsplit(captured["code"]).query)
                code = (query.get("code") or [""])[0]
                if not code:
                    raise RuntimeError(
                        f"Callback URL carried no code parameter: {captured['code']}"
                    )
                log.info("Captured OAuth authorization code (length=%d)", len(code))
                return code

            # No callback navigation: read the page's own error text (the
            # SPA renders QuickAuth's emsg for bad password / TOTP / block).
            body_snippet = ""
            try:
                body_snippet = page.inner_text("body")[:400].replace("\n", " ")
            except Exception:
                pass
            raise RuntimeError(
                f"OAuth login did not reach the callback within "
                f"{timeout_seconds:.0f}s (last URL: {page.url}). "
                f"Page said: {body_snippet or '(empty)'}"
            )
        finally:
            browser.close()


def shoonya_gen_access_token(client_id: str, secret_key: str, code: str) -> str:
    """Exchange the OAuth authorization code for an access token (GenAcsTok).

    checksum = SHA-256(client_id + secret_key + code), per Shoonya's docs.
    """
    checksum = hashlib.sha256(f"{client_id}{secret_key}{code}".encode()).hexdigest()
    response = _post_jdata(
        f"{SHOONYA_BASE}/GenAcsTok",
        {"code": code, "checksum": checksum},
        timeout=20.0,
    )
    if response.get("stat") != "Ok":
        msg = response.get("emsg") or "Unknown error"
        raise RuntimeError(f"Shoonya GenAcsTok failed: {msg}")
    token = response.get("access_token") or response.get("susertoken")
    if not token:
        raise RuntimeError("Shoonya GenAcsTok returned no access_token")
    return str(token)


def shoonya_probe_limits(susertoken: str, user_id: str) -> bool:
    """Return True if /Limits with the given susertoken succeeds.

    This is the same probe OpenAlgo's own _try_resume_broker_session uses
    (see broker/shoonya/api/funds.py::get_margin_data and the resume logic in
    blueprints/auth.py::_try_resume_broker_session).
    """
    payload = {"uid": user_id, "actid": user_id}
    req = urllib_request.Request(
        f"{SHOONYA_BASE}/Limits",
        data=("jData=" + json.dumps(payload)).encode("utf-8"),
        headers={
            "Content-Type": "text/plain",
            "Authorization": f"Bearer {susertoken}",
        },
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=15.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        # 401/403 -> bad token; anything else -> treat as transient failure
        log.debug("Limits probe HTTP %s for user %s", exc.code, user_id)
        return False
    except urllib_error.URLError as exc:
        log.debug("Limits probe network error: %s", exc.reason)
        return False

    if data.get("stat") != "Ok":
        log.debug("Limits probe non-Ok response: %s", data)
        return False
    return True


# --------------------------------------------------------------------------- #
# OpenAlgo DB integration
# --------------------------------------------------------------------------- #


def import_openalgo_db(openalgo_dir: Path) -> tuple[Any, Any, Any, Any]:
    """Load OpenAlgo's .env, then import its database.auth_db module.

    Returns (db_session, Auth, encrypt_token, upsert_auth). Raises ConfigError
    if API_KEY_PEPPER / FERNET_SALT are missing or auth_db refuses to import.
    """
    load_dotenv(openalgo_dir / ".env", override=False)

    required = ("API_KEY_PEPPER", "FERNET_SALT", "BROKER_API_KEY", "BROKER_API_SECRET")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise ConfigError("OpenAlgo .env is missing required keys: " + ", ".join(missing))

    # auth_db requires its PEPPER at import time. We must import from inside
    # the OpenAlgo checkout so relative modules (utils, websocket_proxy, ...)
    # resolve correctly. The same trick as scripts/extract_broker_token.py.
    # We also chdir into the repo root because OpenAlgo's SQLAlchemy URLs use
    # the three-slash sqlite form ('sqlite:///db/openalgo.db') which is
    # resolved against the current working directory, not the script's dir.
    sys.path.insert(0, str(openalgo_dir))
    os.chdir(openalgo_dir)
    try:
        from database.auth_db import (  # type: ignore[import-not-found]
            Auth,
            db_session,
            encrypt_token,
            upsert_auth,
        )
    except Exception as exc:  # pragma: no cover - import errors are environment-specific
        raise ConfigError(f"Failed to import database.auth_db from {openalgo_dir}: {exc}") from exc

    return db_session, Auth, encrypt_token, upsert_auth


def find_shoonya_auth_row(
    Auth: Any,
    db_session: Any,
    shoonya_user_id: str,
) -> Any:
    """Locate the OpenAlgo Auth row that corresponds to this Shoonya account.

    OpenAlgo stores one row per OpenAlgo user (the column is named `name`).
    Preferred: the row whose broker column is 'shoonya'. After a web-UI
    logout, however, OpenAlgo *clears* that row (broker='', auth='', revoked)
    instead of deleting it — so as a fallback, when this instance has exactly
    one auth row at all, use it: `upsert_auth()` will restore broker/auth on
    the next successful login.
    """
    session = db_session()
    try:
        rows = session.query(Auth).order_by(Auth.id.desc()).all()
    finally:
        session.close()

    shoonya_rows = [row for row in rows if row.broker == "shoonya"]
    if shoonya_rows:
        rows = shoonya_rows
    elif len(rows) == 1:
        log.warning(
            "No shoonya auth row found, but a single auth row exists (name=%s, "
            "broker=%r, revoked=%s) — likely cleared by a web-UI logout. Using "
            "it; upsert_auth() will restore broker='shoonya' on login.",
            rows[0].name,
            rows[0].broker,
            rows[0].is_revoked,
        )
    else:
        raise ConfigError(
            "No shoonya Auth row in OpenAlgo DB. Log in once via the web UI "
            "so OpenAlgo can create the row, then re-run this script."
        )

    if len(rows) > 1:
        log.warning(
            "Found %d candidate auth rows; using the most recent (name=%s). "
            "If this is not your account, clean up db/openalgo.db manually.",
            len(rows),
            rows[0].name,
        )

    return rows[0]


def read_existing_token(Auth: Any, db_session: Any, row: Any) -> str | None:
    """Decrypt the susertoken already stored in the Auth row, or None."""
    from database.auth_db import decrypt_token  # type: ignore[import-not-found]

    session = db_session()
    try:
        fresh = session.query(Auth).filter(Auth.id == row.id).first()
        if not fresh or not fresh.auth:
            return None
        return decrypt_token(fresh.auth)
    finally:
        session.close()


def write_new_token(
    upsert_auth: Any,
    row: Any,
    new_susertoken: str,
) -> None:
    """Write the new susertoken through OpenAlgo's own upsert_auth().

    upsert_auth (database/auth_db.py:505) handles Fernet encryption, the
    multi-session resume gate (won't tear down the WS feed unless the token
    actually changed), the ZMQ cache-invalidation publish (for the out-of-
    process WS proxy), and the order-update adapter lifecycle. Reusing it
    means we follow the project's tested invariants instead of duplicating
    them in this script.
    """
    upsert_auth(
        name=row.name,
        auth_token=new_susertoken,
        broker="shoonya",
        feed_token=None,  # Shoonya stores the susertoken in `auth`, not `feed_token`
        user_id=row.user_id,
        revoke=False,
    )
    log.info("Wrote new susertoken via upsert_auth for OpenAlgo user %s", row.name)


# --------------------------------------------------------------------------- #
# Gunicorn reload
# --------------------------------------------------------------------------- #


def reload_gunicorn(cfg: dict[str, str]) -> None:
    """Force the in-process auth_cache in the long-running Flask worker to
    pick up the new token. Without this, /api/v1/ calls will keep serving the
    cached (stale) token for up to ~18 hours.

    Three modes:
      systemd: `sudo systemctl reload openalgo` (gunicorn master recycles
               workers gracefully; eventlet single-worker setup means a brief
               ~2-5s drop in availability, the WS proxy is out-of-process and
               unaffected).
      pidfile: SIGHUP to the PID in OPENALGO_GUNICORN_PIDFILE.
      none:    do nothing (operator accepts the cache-staleness trade-off).
    """
    mode = cfg["reload_mode"]
    if mode == "none":
        log.warning(
            "OPENALGO_RELOAD_MODE=none: the running gunicorn worker's "
            "auth_cache will keep serving the old token until TTL expiry. "
            "/api/v1/ calls will fail with 401 until the worker is reloaded."
        )
        return

    if mode == "systemd":
        log.info("Restarting openalgo systemd service...")
        # A plain `systemctl reload` is not applicable to the Type=simple
        # app.py unit, and the Flask worker's auth_cache would otherwise
        # serve the old token until the 03:00 IST session-expiry TTL. A
        # restart (~20s) is the reliable way to pick up the fresh token;
        # it only runs after a real re-login, i.e. when the old token was
        # already dead.
        try:
            subprocess.run(
                ["sudo", "-n", "systemctl", "restart", "openalgo"],
                check=True,
                timeout=60,
                capture_output=True,
            )
        except FileNotFoundError:
            log.warning("`sudo` not found; falling back to direct systemctl call")
            subprocess.run(
                ["systemctl", "restart", "openalgo"],
                check=True,
                timeout=60,
                capture_output=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            raise RuntimeError(f"systemctl restart failed: {stderr or exc}") from exc
        log.info("systemctl restart OK")
        return

    # pidfile mode
    pidfile = Path(cfg["pidfile"])
    if not pidfile.is_file():
        raise RuntimeError(f"Gunicorn PID file not found: {pidfile}")
    pid = int(pidfile.read_text().strip().split()[0])
    log.info("Sending SIGHUP to gunicorn master PID %d", pid)
    os.kill(pid, signal.SIGHUP)


# --------------------------------------------------------------------------- #
# Notification
# --------------------------------------------------------------------------- #


def notify(cfg: dict[str, str], title: str, body: str, status: str) -> None:
    """POST a small JSON payload to NOTIFICATION_WEBHOOK. No-op if unconfigured.

    status is one of: ok, noop, error.
    """
    webhook = cfg.get("notification_webhook", "")
    if not webhook:
        return
    payload: dict[str, Any] = {
        "status": status,
        "title": title,
        "body": body,
        "host": os.uname().nodename,
        "time": datetime.now(UTC).isoformat(),
    }
    chat_id = cfg.get("notification_chat_id", "")
    if "api.telegram.org" in webhook and chat_id:
        # Telegram Bot API shape
        payload = {"chat_id": chat_id, "text": f"{title}\n{body}"}

    try:
        req = urllib_request.Request(
            webhook,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=10.0) as resp:
            log.debug("Notification webhook responded %s", resp.status)
    except Exception as exc:
        # Never let a notification failure fail the whole run.
        log.warning("Notification webhook failed: %s", exc)


# --------------------------------------------------------------------------- #
# End-to-end check
# --------------------------------------------------------------------------- #


def verify_via_openalgo(cfg: dict[str, str]) -> bool:
    """Optional: hit a lightweight authenticated endpoint to confirm the new
    token flows all the way through. Uses OPENALGO_API_KEY + /api/v1/funds.
    Returns True if it gets a 2xx, False otherwise. Never raises."""
    api_key = cfg.get("openalgo_api_key", "")
    if not api_key:
        log.debug("OPENALGO_API_KEY not set — skipping end-to-end verification")
        return True  # treat as success, we can't verify

    openalgo_dir = Path(cfg["openalgo_dir"])
    host_server_env = (
        _read_env_value(openalgo_dir / ".env", "HOST_SERVER") or "http://127.0.0.1:5000"
    )
    host_server = host_server_env.strip().strip("'\"")
    url = f"{host_server.rstrip('/')}/api/v1/funds"

    try:
        req = urllib_request.Request(
            url,
            data=json.dumps({"apikey": api_key}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=15.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            ok = resp.status == 200 and data.get("status") == "success"
            log.info("End-to-end /api/v1/funds check: %s", "OK" if ok else f"FAILED: {data}")
            return ok
    except Exception as exc:
        log.warning("End-to-end /api/v1/funds check failed: %s", exc)
        return False


def fetch_nifty_ltp(cfg: dict[str, str]) -> str | None:
    """Pull the NIFTY index quote through OpenAlgo's API as a market-data
    sanity check (read-only; proves the session works on the data path, not
    just auth). Returns the formatted LTP, or None when unavailable (market
    feed down, master contracts missing, ...). Never raises."""
    api_key = cfg.get("openalgo_api_key", "")
    if not api_key:
        return None

    openalgo_dir = Path(cfg["openalgo_dir"])
    host_server = (
        _read_env_value(openalgo_dir / ".env", "HOST_SERVER") or "http://127.0.0.1:5000"
    ).strip().strip("'\"")
    url = f"{host_server.rstrip('/')}/api/v1/quotes"

    try:
        req = urllib_request.Request(
            url,
            data=json.dumps(
                {
                    "apikey": api_key,
                    "symbol": cfg["nifty_symbol"],
                    "exchange": cfg["nifty_exchange"],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib_request.urlopen(req, timeout=15.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if resp.status == 200 and data.get("status") == "success":
            ltp = float(data.get("data", {}).get("ltp") or 0)
            if ltp > 0:
                ltp_str = f"{ltp:,.2f}"
                log.info("NIFTY market-data check: OK (LTP %s)", ltp_str)
                return ltp_str
        log.warning("NIFTY market-data check returned no usable LTP: %s", str(data)[:200])
    except Exception as exc:
        log.warning("NIFTY market-data check failed: %s", exc)
    return None


def _read_env_value(env_path: Path, key: str) -> str | None:
    """Tiny .env reader for a single key — no third-party dep required."""
    if not env_path.is_file():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip().strip("'\"")
    return None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--script-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Directory containing this script and its .env (default: alongside the script)",
    )
    p.add_argument(
        "--check-only",
        action="store_true",
        help="Probe the existing token and exit without re-logging in. Useful for cron health checks.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Skip the idempotency probe and always run a fresh OAuth login. Use sparingly.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the OAuth login and the Limits probe, but do NOT write to the DB or reload gunicorn.",
    )
    return p.parse_args()


def perform_login_and_validate(
    cfg: dict[str, str], client_id: str, secret_key: str
) -> str:
    """Run one headless OAuth login and return a Limits-validated susertoken.

    Raises RuntimeError on failure. Two success paths:
      1. We capture the authorization code and exchange it via GenAcsTok.
      2. OpenAlgo's own callback consumes the single-use code first (the
         browser redirect also reaches the OpenAlgo server) and writes the
         fresh token into its DB — we then read and validate that token.
    """
    host_server = (_read_env_value(Path(cfg["openalgo_dir"]) / ".env", "HOST_SERVER") or "").strip("'\"")
    redirect_host = urlsplit(host_server).netloc

    if not cfg["shoonya_password"]:
        raise RuntimeError(
            "SHOONYA_PASSWORD is empty in auto_login_shoonya/.env — the headless "
            "OAuth login form requires the real password. Re-add it to re-enable "
            "automatic re-login."
        )

    code = shoonya_oauth_code(
        client_id=client_id,
        user_id=cfg["shoonya_user_id"],
        password=cfg["shoonya_password"],
        totp_secret=cfg["shoonya_totp_secret"],
        timeout_seconds=cfg["login_timeout_seconds"],
        redirect_host=redirect_host,
    )

    def _db_token() -> str:
        db_session, Auth, _encrypt, _upsert = import_openalgo_db(Path(cfg["openalgo_dir"]))
        auth_row = find_shoonya_auth_row(Auth, db_session, cfg["shoonya_user_id"])
        time.sleep(2)  # give OpenAlgo's own callback write a moment to land
        return read_existing_token(Auth, db_session, auth_row) or ""

    if code:
        try:
            token = shoonya_gen_access_token(client_id, secret_key, code)
            log.info("GenAcsTok returned access_token (length=%d)", len(token))
        except RuntimeError as exc:
            log.info(
                "GenAcsTok failed (%s) — the OpenAlgo callback likely consumed the "
                "code first; trying the DB-written token instead.",
                exc,
            )
            token = _db_token()
            if not token:
                raise RuntimeError(f"GenAcsTok failed and no DB token available: {exc}") from exc
    else:
        log.info("No in-browser code; using the token OpenAlgo's callback wrote to its DB.")
        token = _db_token()
        if not token:
            raise RuntimeError("OAuth flow completed but no code was captured and no DB token is available")

    if not shoonya_probe_limits(token, cfg["shoonya_user_id"]):
        raise RuntimeError("Shoonya /Limits rejected the freshly-minted token")
    log.info("New susertoken validated by Shoonya.")
    return token


def main() -> int:
    args = parse_args()
    try:
        cfg = load_config(args.script_dir)
    except ConfigError as exc:
        # Logging may not be configured yet; print directly.
        print(f"[FATAL] Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    # Resolve the log file path against the script directory (not cwd, which
    # will be chdir'd into the OpenAlgo repo later for sqlite to resolve
    # relative DB paths).
    log_file_path: str | None = None
    if not args.dry_run and cfg["log_file"]:
        log_file_path = str((args.script_dir / cfg["log_file"]).resolve())
    setup_logging(log_file_path)

    log.info(
        "=== auto_login_shoonya start (check_only=%s force=%s dry_run=%s) ===",
        args.check_only,
        args.force,
        args.dry_run,
    )

    try:
        db_session, Auth, encrypt_token, upsert_auth = import_openalgo_db(Path(cfg["openalgo_dir"]))
    except ConfigError as exc:
        log.error("Config error: %s", exc)
        notify(cfg, "OpenAlgo auto-login FAILED", str(exc), status="error")
        return EXIT_CONFIG

    # Resolve the Shoonya OAuth client_id + secret from BROKER_API_KEY/SECRET
    # (BROKER_API_KEY format: userid:::client_id)
    openalgo_dir = Path(cfg["openalgo_dir"])
    broker_api_key = _read_env_value(openalgo_dir / ".env", "BROKER_API_KEY") or ""
    broker_api_secret = _read_env_value(openalgo_dir / ".env", "BROKER_API_SECRET") or ""
    if ":::" not in broker_api_key:
        log.error("BROKER_API_KEY in OpenAlgo .env is not in 'userid:::client_id' format")
        return EXIT_CONFIG
    shoonya_userid_in_oakey, shoonya_client_id = broker_api_key.split(":::", 1)
    shoonya_client_id = shoonya_client_id.strip()
    if cfg["shoonya_user_id"] != shoonya_userid_in_oakey:
        log.warning(
            "SHOONYA_USER_ID in script .env (%s) does not match the userid part of "
            "OpenAlgo's BROKER_API_KEY (%s). Continuing — update the script's .env "
            "if this is wrong.",
            cfg["shoonya_user_id"],
            shoonya_userid_in_oakey,
        )

    # Locate the Auth row
    try:
        auth_row = find_shoonya_auth_row(Auth, db_session, cfg["shoonya_user_id"])
    except ConfigError as exc:
        log.error("%s", exc)
        notify(cfg, "OpenAlgo auto-login FAILED", str(exc), status="error")
        return EXIT_CONFIG

    log.info(
        "Found Auth row: name=%s broker=%s user_id=%s is_revoked=%s",
        auth_row.name,
        auth_row.broker,
        auth_row.user_id,
        auth_row.is_revoked,
    )

    # Idempotency probe. --check-only always probes (it's a health check).
    # --dry-run / normal run probes unless --force is set. --force skips
    # the probe and goes straight to the OAuth login.
    should_probe = (not args.force) and (args.check_only or not args.dry_run)
    if should_probe:
        existing_token = read_existing_token(Auth, db_session, auth_row)
        if existing_token and not auth_row.is_revoked:
            log.info("Probing Shoonya /Limits with existing token...")
            if shoonya_probe_limits(existing_token, cfg["shoonya_user_id"]):
                ltp = fetch_nifty_ltp(cfg)
                nifty = f" NIFTY LTP: {ltp}." if ltp else ""
                log.info("Existing broker session is still valid. No action needed.")
                notify(cfg, "OpenAlgo broker: still valid", f"No re-login required.{nifty}", status="noop")
                return EXIT_OK
            log.info("Existing token is rejected by Shoonya — proceeding with re-login.")
        else:
            log.info("No existing token (or revoked) — proceeding with re-login.")

    if args.check_only:
        log.info("--check-only set and existing token is invalid; exiting 1")
        return EXIT_NETWORK

    # Run the OAuth login with retries
    attempt = 0
    last_error: Exception | None = None
    while attempt < cfg["retry_max"]:
        attempt += 1
        try:
            new_token = perform_login_and_validate(cfg, shoonya_client_id, broker_api_secret.strip())

            if args.dry_run:
                log.info("--dry-run set; not writing to DB or reloading gunicorn")
                notify(
                    cfg,
                    "OpenAlgo auto-login (dry-run) OK",
                    f"New susertoken validated. User={cfg['shoonya_user_id']}.",
                    status="ok",
                )
                return EXIT_OK

            write_new_token(upsert_auth, auth_row, new_token)
            reload_gunicorn(cfg)

            # Give the restarted app time to boot before the end-to-end probe
            # (right after `systemctl restart` Caddy still answers 502).
            time.sleep(25)
            ok = verify_via_openalgo(cfg)
            if not ok:
                log.warning(
                    "End-to-end /api/v1/ check failed. The token is in the DB and "
                    "Shoonya accepts it, but the running Flask worker may still be "
                    "serving the stale cached token. A second reload may be needed."
                )

            msg = f"User {cfg['shoonya_user_id']}: new session minted and verified."
            ltp = fetch_nifty_ltp(cfg)
            if ltp:
                msg += f" NIFTY LTP: {ltp}."
            log.info(msg)
            notify(cfg, "OpenAlgo broker: re-logged in", msg, status="ok")
            return EXIT_OK

        except RuntimeError as exc:
            last_error = exc
            msg = str(exc).lower()
            if (
                "invalid password" in msg
                or "password is empty" in msg
                or "invalid totp" in msg
                or "invalid otp" in msg
                or "factor2" in msg
                or "invalid user id" in msg
                or "captcha" in msg
                or "user blocked" in msg
                or "session expired" in msg
                or "invalid input" in msg
                or "invalid session key" in msg
                or "quickauth rejected" in msg
                or "getauthcode failed" in msg
                or "password is empty" in msg
            ) and "gateway error" not in msg and "502" not in msg and "did not reach the callback" not in msg:
                # Auth-class errors don't benefit from retry
                log.error("Authentication failure (not retrying): %s", exc)
                notify(
                    cfg,
                    "OpenAlgo auto-login FAILED (auth)",
                    f"User {cfg['shoonya_user_id']}: {exc}",
                    status="error",
                )
                return EXIT_AUTH
            if attempt < cfg["retry_max"]:
                delay = cfg["retry_base_delay"] * (2 ** (attempt - 1))
                log.warning(
                    "Attempt %d/%d failed: %s. Retrying in %.1fs...",
                    attempt,
                    cfg["retry_max"],
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                log.error("All %d attempts failed.", cfg["retry_max"])
        except Exception as exc:  # pragma: no cover - defensive
            last_error = exc
            log.exception("Unexpected error: %s", exc)
            if attempt < cfg["retry_max"]:
                delay = cfg["retry_base_delay"] * (2 ** (attempt - 1))
                time.sleep(delay)
            else:
                break

    err = f"{type(last_error).__name__}: {last_error}" if last_error else "unknown"
    log.error("Giving up after %d attempts. Last error: %s", cfg["retry_max"], err)
    notify(
        cfg,
        "OpenAlgo auto-login FAILED",
        f"User {cfg['shoonya_user_id']}: {err}",
        status="error",
    )
    return EXIT_NETWORK if last_error and "network" in err.lower() else EXIT_GENERIC


if __name__ == "__main__":
    sys.exit(main())
