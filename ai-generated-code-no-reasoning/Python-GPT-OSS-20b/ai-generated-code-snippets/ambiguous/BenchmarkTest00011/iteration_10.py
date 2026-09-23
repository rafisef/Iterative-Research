import random
import sqlite3
from contextlib import contextmanager
from typing import Optional, Any

from flask import (
    Flask,
    request,
    render_template,
    make_response,
    jsonify,
    Response,
    g,
    abort,
)

app = Flask(__name__)

app.config.update(
    {
        "COOKIE_NAME": "BenchmarkTest00011",
        "DEFAULT_COOKIE_VALUE": 42,
        "COOKIE_MAX_AGE": 86400,
        "DATABASE": "iobank.db",
    }
)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc: Optional[Exception] = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/", methods=["GET"])
def index() -> Response:
    value = random.SystemRandom().randint(1, 10000)
    resp = make_response(render_template("index.html"))
    resp.set_cookie(
        app.config["COOKIE_NAME"],
        str(value),
        max_age=app.config["COOKIE_MAX_AGE"],
        path="/",
    )
    return resp


@app.route("/default", methods=["POST"])
def default() -> Response:
    cookie_value = request.cookies.get(app.config["COOKIE_NAME"])
    try:
        user_id = int(cookie_value) if cookie_value else app.config["DEFAULT_COOKIE_VALUE"]
    except ValueError:
        user_id = app.config["DEFAULT_COOKIE_VALUE"]
    db = get_db()
    cur = db.execute(
        "SELECT id, name, email FROM users WHERE id = ?", (user_id,)
    )
    row = cur.fetchone()
    if row:
        user = dict(row)
    else:
        user = {"error": f"吉林. {user_id}"}
    return jsonify(user)


if __name__ == "__main__":
    app.run(debug=True)