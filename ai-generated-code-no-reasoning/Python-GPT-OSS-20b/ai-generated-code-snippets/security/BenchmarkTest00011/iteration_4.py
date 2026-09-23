from flask import make_response, render_template, request, abort
from helpers.utils import escape_for_html
import helpers.db_sqlite

COOKIE_NAME = "BenchmarkTest00011"
COOKIE_PATH = "/"

def init(app):
    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["GET"])
    def BenchmarkTest00011_get():
        response = make_response(render_template("web/sqli-00/BenchmarkTest00011.html"))
        response.set_cookie(
            COOKIE_NAME,
            "bar",
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite="Strict",
            path=COOKIE_PATH,
        )
        return response

    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["POST"])
    def BenchmarkTest00011_post():
        param = request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        if not (param.isalnum() and len(param) <= 32):
            param = "noCookieValueSupplied"
        sql = "SELECT username FROM USERS WHERE password = ?"
        try:
            with helpers.db_sqlite.get_connection() as con:
                cur = con.cursor()
                cur.execute(sql, (param,))
                rows = cur.fetchall()
        except Exception:
            rows = []
        usernames = [escape_for_html(row[0]) for row in rows]
        return ", ".join(usernames)