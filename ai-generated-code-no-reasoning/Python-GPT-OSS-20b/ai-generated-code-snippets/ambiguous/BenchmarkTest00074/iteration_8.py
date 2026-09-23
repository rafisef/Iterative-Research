import logging
import os
import urllib.parse
from flask import make_response, request, render_template, redirect, url_for, Response
from helpers.utils import escape_for_html

log = logging.getLogger(__name__)

COOKIE_NAME = os.getenv("BENCHMARK_COOKIE_NAME", "BenchmarkTest00074")
MAX_COOKIE_AGE = int(os.getenv("BENCHMARK_COOKIE_MAX_AGE", "180"))

def _set_cookie(resp: Response, value: str, max_age: int = MAX_COOKIE_AGE) -> None:
    resp.set_cookie(
        COOKIE_NAME,
        value,
        max_age=max_age,
        secure=request.is_secure,
        path=request.script_root or "/",
        domain=request.host.split(":")[0] if request.host else None,
        samesite="Lax",
        httponly=True,
    )

def _get_cookie_value() -> str:
    return request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")

def _decode_cookie(value: str) -> str:
    try:
        return urllib.parse.unquote_plus(value)
    except Exception:
        log.exception("Failed to decode cookie value")
        return "invalid"

def init(app):
    @app.route("/benchmark/codeinj-00/BenchmarkTest00074", methods=["GET", "POST"])
    def benchmark_test_00074() -> Response:
        if request.method == "GET":
            resp = make_response(render_template("web/codeinj-00/BenchmarkTest00074.html"))
            _set_cookie(resp, "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27")
            return resp
        cookie_val = _get_cookie_value()
        decoded = _decode_cookie(cookie_val)
        return f"Received code: {escape_for_html(decoded)}"

    @app.route("/benchmark/codeinj-00/BenchmarkTest00074/clear", methods=["POST"])
    def clear_cookie() -> Response:
        resp = make_response(redirect(url_for("benchmark_test_00074")))
        _set_cookie(resp, "", max_age=0)
        return resp