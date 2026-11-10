"""Deliberately vulnerable Flask application.

FOR TESTING THE ANALYZER ONLY. Never deploy this code.
The [Kxx] tags are neutral markers used by evaluation/evaluate.py; the meaning of each tag
is stored separately in samples/ground_truth.json. Some tagged lines are safe on purpose.
"""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

app = Flask(__name__)
app.secret_key = "flask-insecure-7f3a9c2e1b"  # [K01]
DB_PASSWORD = "Pr0d-DB-pass!2024"  # [K02]
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # [K03]


def get_db():
    return sqlite3.connect("shop.db")


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    cur = get_db().cursor()
    cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")  # [K04]
    return str(cur.fetchall())


@app.route("/search")
def search():
    term = request.args.get("q", "")
    query = f"SELECT name, price FROM products WHERE name LIKE '%{term}%'"
    rows = get_db().execute(query).fetchall()  # [K05]
    return {"rows": rows}


@app.route("/product/<int:product_id>")
def product(product_id):
    row = get_db().execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()  # [K06]
    return {"row": row}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    output = os.popen("ping -c 1 " + host).read()  # [K07]
    return {"output": output}


@app.route("/convert", methods=["POST"])
def convert():
    filename = request.form["file"]
    subprocess.run(f"convert {filename} out.png", shell=True)  # [K08]
    return "ok"


@app.route("/status")
def status():
    result = subprocess.run(["uptime"], capture_output=True, text=True)  # [K09]
    return result.stdout


@app.route("/calc")
def calc():
    expression = request.args.get("expr")
    return str(eval(expression))  # [K10]


@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    return f"<h1>Hello {name}</h1>"  # [K11]


@app.route("/card")
def card():
    title = request.args.get("title", "")
    return render_template_string("<div class='card'>" + title + "</div>")  # [K12]


@app.route("/download")
def download():
    name = request.args.get("name")
    return send_file(os.path.join("uploads", name))  # [K13]


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    response = requests.get(url, timeout=5)  # [K14]
    return response.text


@app.route("/go")
def go():
    return redirect(request.args.get("next"))  # [K15]


@app.route("/restore", methods=["POST"])
def restore():
    session_data = pickle.loads(request.data)  # [K16]
    return str(session_data)


@app.route("/import", methods=["POST"])
def import_config():
    config = yaml.load(request.data)  # [K17]
    return str(config)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # [K18]


def make_reset_token():
    return str(random.randint(100000, 999999))  # [K19]


def call_partner_api(payload):
    return requests.post("https://partner.example.com/api", json=payload, verify=False, timeout=5)  # [K20]


def pick_banner(banners):
    return random.choice(banners)  # [K21]


def file_checksum(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()  # [K22]


@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    # any logged-in user can read any invoice: there is no ownership check
    row = get_db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()  # [K24]
    return {"invoice": row}


def read_template(name):
    with open("templates/" + name) as handle:  # [K25]
        return handle.read()


@app.route("/preview")
def preview():
    return read_template(request.args.get("tpl"))


def run_report(conn, where_clause):
    sql = "SELECT * FROM orders WHERE " + where_clause
    return conn.execute(sql).fetchall()  # [K26]


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # [K23]
