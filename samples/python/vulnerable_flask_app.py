"""Small Flask service used as a vulnerable test fixture (every issue is labelled with EXPECT)."""
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, redirect, request, render_template_string, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-dev-key-123"  # EXPECT: HARDCODED_SECRET
log = logging.getLogger(__name__)
DB = "shop.db"


def get_db():
    """Open the database."""
    return sqlite3.connect(DB)


@app.route("/user")
def find_user():
    """Look a user up by name."""
    name = request.args.get("name")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # EXPECT: SQL_INJECTION
    return str(cur.fetchall())


@app.route("/search")
def search():
    """Search products."""
    term = request.args.get("q", "")
    query = f"SELECT id, title FROM products WHERE title LIKE '%{term}%'"
    rows = get_db().execute(query).fetchall()  # EXPECT: SQL_INJECTION
    return {"rows": rows}


@app.route("/greet")
def greet():
    """Greet the visitor."""
    who = request.args.get("who", "guest")
    return "<h1>Hello " + who + "</h1>"  # EXPECT: XSS


@app.route("/render")
def render():
    """Render a user supplied template."""
    tpl = request.args.get("tpl")
    return render_template_string(tpl)  # EXPECT: SSTI


@app.route("/ping")
def ping():
    """Ping a host."""
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()  # EXPECT: COMMAND_INJECTION


@app.route("/convert")
def convert():
    """Convert a file."""
    fname = request.args.get("file")
    subprocess.run("convert " + fname + " out.png", shell=True)  # EXPECT: COMMAND_INJECTION
    return "ok"


@app.route("/download")
def download():
    """Send a file from disk."""
    name = request.args.get("name")
    return send_file(os.path.join("/srv/files", name))  # EXPECT: PATH_TRAVERSAL


@app.route("/fetch")
def fetch():
    """Fetch a remote page."""
    url = request.args.get("url")
    return requests.get(url, timeout=5).text  # EXPECT: SSRF


@app.route("/go")
def go():
    """Redirect after login."""
    target = request.args.get("next")
    return redirect(target)  # EXPECT: OPEN_REDIRECT


@app.route("/restore", methods=["POST"])
def restore():
    """Restore a session blob."""
    blob = request.data
    return str(pickle.loads(blob))  # EXPECT: INSECURE_DESERIALIZATION


@app.route("/calc")
def calc():
    """Evaluate an expression."""
    expr = request.args.get("expr")
    return str(eval(expr))  # EXPECT: CODE_INJECTION


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])  # EXPECT: BROKEN_ACCESS_CONTROL
def delete_user(user_id):
    """Delete a user."""
    get_db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "deleted"


def hash_password(password):
    """Hash a password."""
    return hashlib.md5(password.encode()).hexdigest()  # EXPECT: WEAK_CRYPTO


def reset_token():
    """Create a password reset token."""
    return str(random.randint(100000, 999999))  # EXPECT: INSECURE_RANDOM


def load_config(path):
    """Load YAML configuration."""
    with open(path) as fh:
        return yaml.load(fh)  # EXPECT: INSECURE_DESERIALIZATION


def call_partner(payload):
    """Post data to a partner API."""
    return requests.post("https://partner.example/api", json=payload, verify=False, timeout=5)  # EXPECT: TLS_VERIFY_DISABLED


def read_claims(token):
    """Read JWT claims."""
    return jwt.decode(token, options={"verify_signature": False})  # EXPECT: INSECURE_AUTH


def login(user, password):
    """Log a login attempt."""
    log.info("login attempt user=%s password=%s", user, password)  # EXPECT: SENSITIVE_LOGGING
    return True


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # EXPECT: DEBUG_ENABLED
