"""Account service written to follow the secure coding rules (no findings expected)."""
import hashlib
import logging
import os
import secrets
import sqlite3
import subprocess
from html import escape
from pathlib import Path

import requests
import yaml

LOG = logging.getLogger(__name__)
BASE_DIR = Path("/srv/files").resolve()
API_TOKEN = os.environ.get("API_TOKEN")
ALLOWED_HOSTS = {"api.example.com"}


def find_user(conn, name):
    """Return users whose name matches, using a bound parameter."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cur.fetchall()


def render_greeting(who):
    """Return an HTML greeting with the visitor name escaped."""
    return "<h1>Hello " + escape(who) + "</h1>"


def ping(host):
    """Ping a validated host without invoking a shell."""
    if not host.replace(".", "").replace("-", "").isalnum():
        raise ValueError("bad host")
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=True).stdout


def read_report(name):
    """Read a file only if it stays inside BASE_DIR."""
    target = (BASE_DIR / name).resolve()
    if BASE_DIR not in target.parents:
        raise PermissionError("outside base directory")
    return target.read_text(encoding="utf-8")


def fetch(host, path):
    """Fetch from an allow-listed host."""
    if host not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(f"https://{host}/{path}", timeout=5).text


def hash_password(password, salt):
    """Hash a password with PBKDF2-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def new_reset_token():
    """Create an unpredictable reset token."""
    return secrets.token_urlsafe(32)


def load_config(path):
    """Load YAML configuration safely."""
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def log_login(user):
    """Record a login without logging secrets."""
    LOG.info("login attempt user=%s", user)


def total_price(prices, tax_rate):
    """Sum prices and add tax."""
    subtotal = sum(prices)
    return subtotal + subtotal * tax_rate


def open_db(path):
    """Open a database connection."""
    return sqlite3.connect(path)
