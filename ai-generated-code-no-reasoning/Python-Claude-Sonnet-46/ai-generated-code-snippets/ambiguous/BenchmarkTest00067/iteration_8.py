import urllib.parse
from urllib.parse import urlparse

import flask
from flask import make_response, redirect, render_template, request

ALLOWED_HOSTS: frozenset[str] = frozenset({'localhost'})
ALLOWED_SCHEMES: frozenset[str] = frozenset({'http', 'https'})
COOKIE_NAME: str = 'BenchmarkTest00067'
DEFAULT_COOKIE_VALUE: str = 'http%3A%2F%2Flocalhost%3A5000%2F'
COOKIE_MAX_AGE: int = 180
ROUTE: str = '/benchmark/redirect-00/BenchmarkTest00067'
TEMPLATE: str = 'web/redirect-00/BenchmarkTest00067.html'


def is_safe_redirect_url(url: str) -> bool:
    if not isinstance(url, str) or not url:
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
            return False
        host = parsed.hostname
        return host is not None and host.lower() in ALLOWED_HOSTS
    except ValueError:
        return False


def _set_benchmark_cookie(response: flask.Response, path: str) -> flask.Response:
    response.set_cookie(
        COOKIE_NAME,
        DEFAULT_COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost',
    )
    return response


def _get_redirect_url() -> str:
    raw = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    return urllib.parse.unquote_plus(raw)


def init(app: flask.Flask) -> None:

    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00067() -> flask.Response:
        if request.method == 'GET':
            response = make_response(render_template(TEMPLATE))
            return _set_benchmark_cookie(response, request.path)

        decoded_url = _get_redirect_url()
        if not is_safe_redirect_url(decoded_url):
            flask.abort(400)
        return redirect(decoded_url, code=302)