import os
import re
import logging
from typing import Optional

from flask import (
    Blueprint,
    request,
    session,
    make_response,
    render_template,
    escape,
    jsonify,
    Response,
)

benchmark_bp = Blueprint("benchmark", __name__)

COOKIE_NAME: str = os.getenv("BENCHMARK_COOKIE_NAME", "BenchmarkTest00072")
SESSION_KEY: str = os.getenv("BENCHMARK_SESSION_KEY", "BenchmarkTest00072")
SESSION_VALUE: str = os.getenv("BENCHMARK_SESSION_VALUE", "12345")
COOKIE_MAX_AGE: int = int(os.getenv("BENCHMARK_COOKIE_MAX_AGE", 180))
COOKIE_PATH: str = os.getenv("BENCHMARK_COOKIE_PATH", "/")
DOMAIN_RE = re.compile(r"^[\w.-]+$")

LOG = logging.getLogger(__name__)


def _cookie_domain() -> Optional[str]:
    host = request.host.split(":")[0]
    return host if DOMAIN_RE.match(host) else None


def _set_secure_cookie(response: Response, name: str, value: str) -> None:
    response.set_cookie(
        name,
        value,
        max_age=COOKIE_MAX_AGE,
        secure=request.is_secure,
        httponly=True,
        samesite="Lax",
        path=COOKIE_PATH,
        domain=_cookie_domain(),
    )


def _validate_cookie(value: Optional[str]) -> bool:
    return bool(value and isinstance(value, str))


@benchmark_bp.after_request
def _set_security_headers(response: Response) -> Response:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    return response


@benchmark_bp.route(
    "/benchmark/trustbound-00/BenchmarkTest00072", methods=["GET", "POST"]
)
def benchmark_test_00072() -> Response:
    if request.method == "GET":
        resp = make_response(render_template("web/trustbound-00/BenchmarkTest00072.html"))
        _set_secure_cookie(resp, COOKIE_NAME, "my-user-id")
        return resp

    cookie_value = request.cookies.get(COOKIE_NAME, "defaultKey")
    if not _validate_cookie(cookie_value):
        LOG.warning("Invalid cookie value: %s", cookie_value)
        cookie_value = "defaultKey"

    session[SESSION_KEY] = SESSION_VALUE
    return jsonify(item=escape(cookie_value), session_value=SESSION_VALUE)


@benchmark_bp.route("/benchmark/trustbound-00/BenchmarkTest00072/clear", methods=["POST"])
def clear_benchmark_test_00072() -> Response:
    resp = make_response(jsonify(status="cleared"))
    resp.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, domain=_cookie_domain())
    session.pop(SESSION_KEY, None)
    return resp


@benchmark_bp.errorhandler(404)
def _handle_404(error) -> tuple[Response, int]:
    return jsonify(error="Not Found"), 404


@benchmark_bp.errorhandler(500)
def _handle_500(error) -> tuple[Response, int]:
    LOG.exception("Internal server error")
    return jsonify(error="Internal Server Error"), 500