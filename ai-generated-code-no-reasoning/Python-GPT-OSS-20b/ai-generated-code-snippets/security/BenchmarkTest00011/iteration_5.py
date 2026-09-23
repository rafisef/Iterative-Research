from flask import make_response, render_template, request, abort
from helpers.utils import escape_for_html
import helpers.db_sqlite

def init(app):
    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["GET"])
    def BenchmarkTest00011_get():
        return render_template("web/sqli-00/BenchmarkTest00011.html")

    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["POST"])
    def BenchmarkTest00011_post():
        param = request.form.get("password", "")
        if not param.isalnum() or len(param) > 32:
            abort(400)
        sql = "SELECT username FROM USERS WHERE password = ?"
        try:
            with helpers.db_sqlite.get_connection() as con:
                cur = con.cursor()
                cur.execute(sql, (param,))
                rows = cur.fetchall()
        except Exception:
            rows = []
        return ", ".join([escape_for_html(row[0]) for row in rows])