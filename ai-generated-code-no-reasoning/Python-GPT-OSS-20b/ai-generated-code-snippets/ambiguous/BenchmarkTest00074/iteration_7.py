import logging
import os
import urllib.parse
from flask import make_response, request, render_template, redirect, url_for
from helpers.utils import escape_for_html

log = logging.getLogger(__name__)

def init(app):
    cookie_name = os.getenv("BENCHMARK_COOKIE_NAME", "BenchmarkTest00074")

    def _set_cookie(resp, value, max_age=180):
        resp.set_cookie(
            cookie_name,
            value,
            max_age=max_age,
            secure=request.is_secure,
            path=request.path,
            domain=request.host.split(":")[0] if request.host else None,
            samesite="Lax",
            httponly=True,
        )

    @app.route("/benchmark/codeinj-00/BenchmarkTest00074", methods=["GET", "POST"])
    def benchmark_test_00074():
        if request.method == "GET":
            resp = make_response(render_template("web/codeinj-00/BenchmarkTest00074.html"))
            _set_cookie(resp, "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27")
            return resp
        param = request.cookies.get(cookie_name, "noCookieValueSupplied")
        try:
            decoded = urllib.parse.unquote_plus(param)
        except Exception:
            log.exception("Failed to decode cookie value")
            decoded = "invalid"
        return f"Received code: {escape_for_html(decoded)}"

    @app.route("/benchmark/codeinj-00/BenchmarkTest00074/clear", methods=["POST"])
    def clear_cookie():
        resp = make_response(redirect(url_for("benchmark_test_00074")))
        _set_cookie(resp, "", max_age=0)
        return resp