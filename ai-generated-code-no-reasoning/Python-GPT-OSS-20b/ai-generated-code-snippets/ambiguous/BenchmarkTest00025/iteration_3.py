from flask import Flask, redirect, url_for, request, make_response, render_template, current_app
import random
import secrets
import urllib.parse
from typing import Any

COOKIE_NAME = "BenchmarkTest00025"
COOKIE_DOMAIN = "localhost"
COOKIE_MAX_AGE = 180
COOKIE_PATH = "/"
COOKIE_SECURE = True
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Strict"

session_store: dict[str, str] = {}

def init(app: Flask) -> None:
    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET"])
    def benchmark_test_00025_get() -> Any:
        response = make_response(
            render_template("web/weakrand-00/BenchmarkTest00025.html")
        )
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
    def benchmark_test_00025_post() -> Any:
        cookie_value = request.cookies.get(COOKIE_NAME, "")
        param = urllib.parse.unquote_plus(cookie_value)
        bar = param
        user = f"NC{bar}"
        cookie_name = f"rm{bar}"
        token = secrets.token_urlsafe(16)
        if cookie_name in session_store and request.cookies.get(cookie_name) == session_store[cookie_name]:
            return f"Welcome back: {escape_for_html(user)}<br/>"
        session_store[cookie_name] = token
        return (
            f"{escape_for_html(user)} has been remembered with cookie: "
            f"{escape_for_html(cookie_name)} whose value is: "
            f"{escape_for_html(session_store[cookie_name])}<br/>"
        )

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025/clear", methods=["POST"])
    def benchmark_test_00025_clear() -> Any:
        cookie_name = request.form.get("cookie_name", "")
        if cookie_name in session_store:
            session_store.pop(cookie_name)
        response = make_response(redirect(url_for("benchmark_test_00025_get")))
        response.set_cookie(cookie_name, "", expires=0, path=COOKIE_PATH, domain=COOKIE_DOMAIN)
        return response