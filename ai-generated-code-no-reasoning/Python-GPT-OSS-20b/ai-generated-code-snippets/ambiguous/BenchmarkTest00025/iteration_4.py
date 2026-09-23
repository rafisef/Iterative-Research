from flask import Flask, redirect, url_for, request, make_response, render_template
from markupsafe import escape
import secrets
import urllib.parse
from typing import Dict

COOKIE_NAME = "BenchmarkTest00025"
COOKIE_DOMAIN = "localhost"
COOKIE_MAX_AGE = 180
COOKIE_PATH = "/"
COOKIE_SECURE = True
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Strict"

session_store: Dict[str, str] = {}


def init(app: Flask) -> None:
    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET"])
    def benchmark_test_00025_get() -> str:
        response = make_response(render_template("web/weakrand-00/BenchmarkTest00025.html"))
        response.set_cookie(
            COOKIE_NAME,
            "whatever",
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=COOKIE_PATH,
            domain=COOKIE_DOMAIN,
            httponly=COOKIE_HTTPONLY,
            samesite=COOKIE_SAMESITE,
        )
        return response

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["POST"])
    def benchmark_test_00025_post() -> str:
        cookie_value = request.cookies.get(COOKIE_NAME, "")
        param = urllib.parse.unquote_plus(cookie_value)
        user = f"NC{param}"
        cookie_name = f"rm{param}"
        token = secrets.token_urlsafe(16)
        if cookie_name in session_store and request.cookies.get(cookie_name) == session_store[cookie_name]:
            return f"Welcome back: {escape(user)}<br/>"
        session_store[cookie_name] = token
        return (
            f"{escape(user)} has been remembered with cookie: "
            f"{escape(cookie_name)} whose value is: "
            f"{escape(session_store[cookie_name])}<br/>"
        )

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025/clear", methods=["POST"])
    def benchmark_test_00025_clear() -> str:
        cookie_name = request.form.get("cookie_name", "")
        session_store.pop(cookie_name, None)
        response = make_response(redirect(url_for("benchmark_test_00025_get")))
        response.delete_cookie(cookie_name, path=COOKIE_PATH, domain=COOKIE_DOMAIN)
        return response