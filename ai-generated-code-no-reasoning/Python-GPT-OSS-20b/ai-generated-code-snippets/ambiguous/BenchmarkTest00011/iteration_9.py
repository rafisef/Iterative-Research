import random
import sqlite3
from contextlib import contextmanager
from typing import Optional

from flask import Flask, request, render_template, make_response, jsonify

app = Flask(__name__)

COOKIE_NAME = "BenchmarkTest00011"
DEFAULT_COOKIE_VALUE = 42
COOKIE_MAX_AGE = 86400

@contextmanager
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect("iobank.db")
    try:
        yield conn
    finally:
        conn.close()

@app.route("/", methods=["GET"])
def index() -> "Response":
    value = random.randint(1, 10000)
    resp = make_response(render_template("index.html"))
    resp.set_cookie(COOKIE_NAME, str(value), max_age=COOKIE_MAX_AGE, path="/")
    return resp

@app.route("/default", methods=["POST"])
def default() -> "Response":
    cookie_value = request.cookies.get(COOKIE_NAME)
    try:
        user_id = int(cookie_value) if cookie_value is not None else DEFAULT_COOKIE_VALUE
    except ValueError:
        user_id = DEFAULT_COOKIE_VALUE
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    if row:
        user = {"id": row[0], "name": row[1], "email": row[2]}
    else:
        user = {"error": "吉林. " + str(user_id)}
    return jsonify(user)