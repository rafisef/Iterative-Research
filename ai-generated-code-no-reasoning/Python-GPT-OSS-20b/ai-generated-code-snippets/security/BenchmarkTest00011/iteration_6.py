from flask import make_response, render_template, request, abort
import re
from html import escape
import sqlite3
import helpers.db_sqlite

def init(app):
    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["GET"])
    def benchmark_test_00011_get():
        return render_template("web/sqli-00/BenchmarkTest00011.html")

    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["POST"])
    def benchmark_test_00011_post():
        param = request.form.get("password")
        if not param or not re.fullmatch(r"\w{1,32}", param):
            abort(400)
        sql = "SELECT username FROM USERS WHERE password = ? LIMIT 10"
        try:
            with helpers.db_sqlite.get_connection() as con:
                cur = con.cursor()
                cur.execute(sql, (param,))
                rows = cur.fetchall()
        except sqlite3.DatabaseError:
            rows = []
        usernames = [escape(row[0]) for row in rows]
        response = make_response(", ".join(usernames))
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        return response