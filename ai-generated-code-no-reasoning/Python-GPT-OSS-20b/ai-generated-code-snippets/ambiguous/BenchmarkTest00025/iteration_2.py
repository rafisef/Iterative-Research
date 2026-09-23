from flask import Flask, redirect, url_for, request, make_response, render_template, current_app
from helpers.utils import escape_for_html, mysession
import random
import secrets
import urllib.parse

COOKIE_NAME = "BenchmarkTest00025"
COOKIE_DOMAIN = "localhost"
COOKIE_MAX_AGE = 180
COOKIE_PATH = "/"
COOKIE_SECURE = True
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Strict"

def init(app: Flask) -> None:
    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET"])
    def benchmark_test_00025_get() -> Flask.response_class:
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
    def benchmark_test_00025_post() -> str:
        cookie_value = request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        param = urllib.parse.unquote_plus(cookie_value)
        superstring = f"90583{param}abcd"
        bar = superstring[5:-5]
        user = f"NC{bar}"
        cookie_name = f"rm{bar}"
        token = secrets.token_urlsafe(16)
        if cookie_name in mysession and request.cookies.get(cookie_name) == mysession[cookie_name]:
            return f"Welcome back: {escape_for_html(user)}<br/>"
        mysession[cookie_name] = token
        return (
            f"{escape_for_html(user)} has been remembered with cookie: "
            f"{escape_for_html(cookie_name)} whose value is: "
            f"{escape_for_html(mysession[cookie_name])}<br/>"
        )