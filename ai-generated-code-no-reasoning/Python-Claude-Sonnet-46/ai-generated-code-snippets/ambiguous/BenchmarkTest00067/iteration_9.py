import urllib.parse
from urllib.parse import urlparse

import flask
from flask import make_response, redirect, render_template, request

ALLOWED_HOSTS: frozenset[str] = frozenset({"localhost"})
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
COOKIE_NAME: str = "BenchmarkTest00067"
DEFAULT_COOKIE_VALUE: str = "http%3A%2F%2Flocalhost%3A5000%2F"
COOKIE_MAX_AGE: int = 180
ROUTE: str = "/benchmark/redirect-00/BenchmarkTest00067"
TEMPLATE: str = "web/redirect-00/BenchmarkTest00067.html"


def is_safe_redirect_url(url: str) -> bool:
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in ALLOWED_SCHEMES
            and bool(parsed.netloc)
            and parsed.hostname is not None
            and parsed.hostname.lower() in ALLOWED_HOSTS
        )
    except ValueError:
        return False


def _set_benchmark_cookie(response: flask.Response, path: str) -> flask.Response:
    response.set_cookie(
        COOKIE_NAME,
        DEFAULT_COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Strict",
        path=path,
        domain="localhost",
    )
    return response


def _get_redirect_url() -> str:
    return urllib.parse.unquote_plus(
        request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    )


def init(app: flask.Flask) -> None:
    @app.route(ROUTE, methods=["GET", "POST"])
    def BenchmarkTest00067() -> flask.Response:
        if request.method == "GET":
            return _set_benchmark_cookie(
                make_response(render_template(TEMPLATE)), request.path
            )

        decoded_url = _get_redirect_url()
        if not is_safe_redirect_url(decoded_url):
            flask.abort(400)

        return redirect(decoded_url, code=302)