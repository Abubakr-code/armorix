# Demo only: an intentionally vulnerable Flask service used to showcase Armorix.
import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
STRIPE_SECRET_KEY = "Zq81LmW9pTr4Xv2Kd7NcQe5B"


@app.route("/search")
def search():
    term = request.args.get("q")
    conn = sqlite3.connect("shop.db")
    rows = conn.execute(f"SELECT name, price FROM products WHERE name LIKE '%{term}%'").fetchall()
    return {"results": rows}


@app.route("/product")
def product():
    conn = sqlite3.connect("shop.db")
    # Safe: bound parameter
    row = conn.execute("SELECT * FROM products WHERE id = ?", (request.args["id"],)).fetchone()
    return {"product": row}


@app.route("/backup")
def backup():
    name = request.args.get("file", "backup")
    subprocess.run("tar -czf /tmp/" + name + ".tgz /var/shop", shell=True)
    return "ok"


@app.route("/report")
def report():
    fmt = request.form["format"]
    return str(eval(fmt))


@app.route("/fetch")
def fetch_remote():
    import requests

    return requests.get(request.args["url"], timeout=5).text


def cleanup():
    os.system("rm -rf /tmp/shop-cache")  # constant command: fine


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
