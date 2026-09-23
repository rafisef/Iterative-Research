from dataclasses import dataclass
from flask import Flask, redirect, request, make_response, render_template, url_for, abort
from markupsafe import escape
import os
import secrets
import urllib.parse
from typing import Dict

@dataclass(frozen=True)
class CookieConfig:
    name: str = "BenchmarkTest00025"
    domain: str = os.getenv("COOKIE_DOMAIN", "localhost")
    max_age: int = 180
    path: str = "/"
    secure: bool = True
    httponly: bool = True
    samesite: str = "Strict"

COOKIE_CONFIG = CookieConfig()
session_store: Dict[str, str] = {}

def set_cookie(resp, name: str, value: str) -> None:
    resp.set_cookie(
        name,
        value,
        max_age=COOKIE_CONFIG.max_age,
        secure=COOKIE_CONFIG.secure,
        path=COOKIE_CONFIG.path,
        domain=COOKIE_CONFIG.domain,
        httponly=COOKIE_CONFIG.httponly,
        samesite=COOKIE_CONFIG.samesite,
    )

def delete_cookie(resp, name: str) -> None:
    resp.delete_cookie(name, path=COOKIE_CONFIG.path, domain=COOKIE_CONFIG.domain)

def init(app: Flask) -> None:
    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET", "POST"])
    def benchmark_test_00025():
        if request.method == "GET":
            resp = make_response(render_template("web/weakrand-00/BenchmarkTest00025.html"))
            set_cookie(resp, COOKIE_CONFIG.name, "whatever")
            return resp
        cookie_value = request.cookies.get(COOKIE_CONFIG.name, "")
        param = urllib.parse.unquote_plus(cookie_value)
        if not param.isalnum():
            abort(400)
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
    def benchmark_test_00025_clear():
        cookie_name = request.form.get("cookie_name", "")
        session_store.pop(cookie_name, None)
        resp = make_response(redirect(url_for("benchmark_test_00025")))
        delete_cookie(resp, cookie_name)
        return resp

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025/clear_all", methods=["POST"])
    def benchmark_test_00025_clear_all():
        session_store.clear()
        resp = make_response(redirect(url_for("benchmark_test_00025")))
        delete_cookie(resp, COOKIE_CONFIG.name)
        return resp

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025/session", methods=["GET"])
    def benchmark_test_00025_session():
        return {"session_store": session_store}