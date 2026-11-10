"""The same features as samples/vulnerable_app/app.py, written safely.

Nothing in this folder is vulnerable, so every finding reported here is a false positive.
Several lines are written to LOOK suspicious (the words eval, password, token, md5 appear)
in order to test the precision of the analyzer.
"""
import ast
import hashlib
import os
import secrets
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, redirect, render_template, request, send_from_directory, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
PASSWORD_MIN_LENGTH = 12
password_label = "Enter your password"
token_url = "https://auth.example.com/oauth/token"
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return {"rows": cur.fetchall()}


@app.route("/search")
def search():
    term = request.args.get("q", "")
    query = "SELECT name, price FROM products WHERE name LIKE ?"
    rows = get_db().execute(query, ("%" + term + "%",)).fetchall()
    return {"rows": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return {"output": result.stdout}


@app.route("/calc")
def calc():
    # eval() is never used here: literal_eval only accepts plain Python literals
    expression = request.args.get("expr", "0")
    return {"value": ast.literal_eval(expression)}


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<h1>Hello {escape(name)}</h1>"


@app.route("/card")
def card():
    return render_template("card.html", title=request.args.get("title", ""))


@app.route("/download")
def download():
    name = secure_filename(request.args.get("name", ""))
    return send_from_directory("uploads", name)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    return requests.get("https://api.example.com/status", timeout=5).text


@app.route("/go")
def go():
    return redirect(url_for("hello"))


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.safe_load(request.data)
    return {"keys": sorted(config)}


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()


def cache_key(data):
    # MD5 only as a fast cache key, not for security
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def make_reset_token():
    return secrets.token_urlsafe(32)


def run_backup():
    subprocess.run("tar czf /tmp/backup.tgz /srv/shop", shell=True, check=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
