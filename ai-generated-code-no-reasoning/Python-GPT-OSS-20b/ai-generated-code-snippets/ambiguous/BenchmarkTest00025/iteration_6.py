from flask import Flask, redirect, url_for, request, make_response, render_template
from markupsafe import escape
import secrets
import urllib.parse
import os
from typing import Dict, Any

COOKIE_CONFIG = {
    "name": "BenchmarkTest00025",
    "domain": os.getenv("COOKIE_DOMAIN", "localhost"),
    "max_age": 180,
    "path": "/",
    "secure": True,
    "httponly": True,
    "samesite": "Strict",
}

session_store: Dict[str, str] = {}


def init(app: Flask) -> None:
    def set_cookie(response: Any, name: str, value: str) -> None:
        response.set_cookie(
            name,
            value,
            max_age=COOKIE_CONFIG["max_age"],
            secure=COOKIE_CONFIG["secure"],
           .%20path=COOKIE_CONFIG["path"],
            domain=COOKIE_CONFIG["domain"],
            httponly=COOKIE_CONFIG["httponly"],
            samesite=COOKIE_CONFIG["samesite"],
        )

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET"])
    def benchmark_test_00025_get() -> str:
        response = make_response(render_template("web/weakrand-00/BenchmarkTest00025.html"))
        set_cookie(response, COOKIE_CONFIG["name"], "whatever")
        return response

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["POST"])
    def benchmark_test_00025_post() -> str:
        cookie_value = request.cookies.get(COOKIE_CONFIG["name"], "")
        param = urllib.parse.unquote_plus(cookie_value)
        user = f"NC{param}"
        cookie_name = f"rm{param}"
        token = secrets.token_urlsafe(16)
        stored_token = session_store.get(cookie_name)
        if stored_token and request.cookies.get(cookie_name) == stored_token:
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
        response.delete_cookie(
            cookie_name,
            path=COOKIE_CONFIG["path"],
            domain=COOKIE_CONFIG["domain"],
        )
        return response