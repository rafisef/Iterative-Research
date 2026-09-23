from flask import make_response, render_template, request, abort
import re
from markupsafe import escape
import sqlite3
import helpers.db_sqlite
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

def init(app):
    csrf.init_app(app)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    @app.after_request
    def apply_secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["X-Download-Options"] = "noopen"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        return response

    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["GET"])
    def benchmark_test_00011_get():
        return render_template("web/sqli-00/BenchmarkTest00011.html")

    @app.route("/benchmark/sqli-00/BenchmarkTest00011", methods=["POST"])
    def benchmark_test_00011_post():
        param = request.form.get("password", "")
        if not param or len(param) > 32 or not param.isascii() or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", param):
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