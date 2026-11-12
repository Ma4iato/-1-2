import hmac
import logging
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque

from flask import Flask, abort, redirect, render_template, request, session
from werkzeug.security import check_password_hash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
audit_logger = logging.getLogger("security.audit")

app = Flask(__name__)

_env_secret = os.environ.get("SECRET_KEY")
if _env_secret:
    app.secret_key = _env_secret
else:
    # Ephemeral cryptographically strong key prevents predictable cookie forgery
    app.secret_key = secrets.token_hex(32)
    audit_logger.warning("SECRET_KEY is not set; generated an ephemeral session key.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)

DB_PATH = os.environ.get("DB_PATH", "demo.sqlite3")

# Sliding-window rate limit for failed login attempts
LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = 5
_failed_login_attempts: dict[str, deque[float]] = defaultdict(deque)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(app.config.get("DB_PATH", DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _get_or_create_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _get_or_create_csrf_token}


def _validate_csrf() -> None:
    expected = session.get("_csrf_token", "")
    provided = request.form.get("csrf_token", "")
    if not expected or not provided or not hmac.compare_digest(expected, provided):
        audit_logger.warning(
            "CSRF validation failed for path=%s ip=%s",
            request.path,
            request.remote_addr,
        )
        abort(403)


def _prune_attempts(client_key: str, now: float) -> deque[float]:
    attempts = _failed_login_attempts[client_key]
    cutoff = now - LOGIN_WINDOW_SECONDS
    while attempts and attempts[0] < cutoff:
        attempts.popleft()
    return attempts


def _is_rate_limited(client_key: str) -> bool:
    attempts = _prune_attempts(client_key, time.monotonic())
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _record_failed_attempt(client_key: str) -> None:
    now = time.monotonic()
    attempts = _prune_attempts(client_key, now)
    attempts.append(now)


def _clear_attempts(client_key: str) -> None:
    _failed_login_attempts.pop(client_key, None)


@app.after_request
def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Server"] = "SecureApp"
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    # Jinja2 template auto-escaping neutralizes reflected XSS (CWE-79)
    return render_template("echo.html", msg=msg)


@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    conn = get_db()
    try:
        cur = conn.cursor()
        pattern = f"%{q}%"
        rows = cur.execute(
            "SELECT id, title, body FROM posts WHERE title LIKE ? OR body LIKE ?",
            (pattern, pattern),
        ).fetchall()
    finally:
        conn.close()
    return render_template("search.html", q=q, rows=rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        _validate_csrf()
        client_ip = request.remote_addr or "unknown"
        if _is_rate_limited(client_ip):
            audit_logger.warning("Rate limit exceeded on /login ip=%s", client_ip)
            return (
                render_template(
                    "login.html",
                    error="Too many failed login attempts. Please try again later.",
                ),
                429,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        try:
            cur = conn.cursor()
            row = cur.execute(
                "SELECT id, username, password FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()

        if row and check_password_hash(row["password"], password):
            _clear_attempts(client_ip)
            session.clear()
            session["user_id"] = row["id"]
            audit_logger.info("Successful login username=%s ip=%s", username, client_ip)
            return redirect("/profile")

        _record_failed_attempt(client_ip)
        audit_logger.warning("Failed login attempt username=%s ip=%s", username, client_ip)
        return render_template("login.html", error="Invalid credentials"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    _validate_csrf()
    user_id = session.get("user_id")
    session.clear()
    audit_logger.info("User logged out user_id=%s ip=%s", user_id, request.remote_addr)
    return redirect("/")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")
    conn = get_db()
    try:
        cur = conn.cursor()
        user = cur.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()
    finally:
        conn.close()
    if not user:
        session.clear()
        return redirect("/login")
    return render_template("profile.html", user=user)


@app.errorhandler(403)
def forbidden(_err):
    return render_template("login.html", error="Invalid or missing CSRF token."), 403


if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
