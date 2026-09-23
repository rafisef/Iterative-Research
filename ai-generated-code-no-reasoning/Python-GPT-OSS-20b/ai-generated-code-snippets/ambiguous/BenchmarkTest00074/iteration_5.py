import logging
import os
import urllib.parse
from flask import (
    current_app,
    make_response,
    request,
    render_template,
    redirect,
    url_for,
)
from helpers.utils import escape_for_html

log = logging.getLogger(__name__)

def init(app):
    cookie_name = os.getenv("BENCHMARK_COOKIE_NAME", "BenchmarkTest00074")
    cookie_domain = request.host.split(":")[0] if request.host else None
    cookie_path = request.path

    def set_cookie(resp, value):
        resp.set_cookie(
            cookie_name,
            value,
            max_age=180,
            secure=request.is_secure,
            path=cookie_path,
            domain=cookie_domain,
            samesite="Lax",
            httponly=True,
        )

    @app.route(
        "/benchmark/codeinj-00/BenchmarkTest00074",
        methods=["GET", "POST"],
    )
    def benchmark_test_00074():
        if request.method == "GET":
            resp = make_response(
                render_template("web/codeinj-00/BenchmarkTest00074.html")
            )
            set_cookie(resp, "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27")
            return resp
        param = request.cookies.get(cookie_name, "noCookieValueSupplied")
        try:
            decoded = urllib.parse.unquote_plus(param)
        except Exception as exc:
            log.exception("Failed to decode cookie value")
            decoded = "invalid"
        return f"Received code: {escape_for_html(decoded)}"

    @app.route(
        "/benchmark/codeinj-00/BenchmarkTest00074/clear",
        methods=["POST"],
    )
    def clear_cookie():
        resp = make_response(redirect(url_for("benchmark_test_00074")))
        resp.set_cookie(
            cookie_name,
            "",
            max_age=0,
            secure=request.is_secure,
            path=cookie_path,
            domain=cookie_domain,
            samesite="Lax",
            httponly=True,
        )
        return resp