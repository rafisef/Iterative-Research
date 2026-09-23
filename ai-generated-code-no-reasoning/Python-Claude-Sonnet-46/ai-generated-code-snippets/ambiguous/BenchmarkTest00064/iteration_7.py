import urllib.parse
from http import HTTPStatus

from flask import make_response, render_template, request

import helpers.utils

COOKIE_MAX_AGE = 180
BENCHMARK_COOKIE_NAME = "BenchmarkTest00064"
OUTPUT_COOKIE_NAME = "SomeCookie"
ROUTE_PATH = "/benchmark/securecookie-00/BenchmarkTest00064"
DEFAULT_COOKIE_VALUE = "noCookieValueSupplied"
LOCALHOST = "localhost"
TEMPLATE_PATH = "web/securecookie-00/BenchmarkTest00064.html"
SAMESITE_POLICY = "Strict"


def _extract_cookie_value(raw_param: str) -> str:
    decoded = urllib.parse.unquote_plus(raw_param)
    escaped = helpers.utils.escape_for_html(decoded)
    return escaped if isinstance(escaped, str) else ""


def _build_cookie_kwargs(path: str, secure: bool = True, httponly: bool = True) -> dict:
    return {
        "secure": secure,
        "httponly": httponly,
        "samesite": SAMESITE_POLICY,
        "path": path,
    }


def _set_benchmark_cookie(response, path: str) -> None:
    kwargs = _build_cookie_kwargs(path)
    kwargs["max_age"] = COOKIE_MAX_AGE
    kwargs["domain"] = LOCALHOST
    response.set_cookie(BENCHMARK_COOKIE_NAME, "whatever", **kwargs)


def _set_output_cookie(response, value: str, path: str) -> None:
    response.set_cookie(OUTPUT_COOKIE_NAME, value, **_build_cookie_kwargs(path))


def _make_get_response(path: str):
    response = make_response(render_template(TEMPLATE_PATH), HTTPStatus.OK)
    _set_benchmark_cookie(response, path)
    return response


def _make_post_response(path: str, raw_param: str):
    cookie_value = _extract_cookie_value(raw_param)
    response_body = (
        f"Created cookie: '{OUTPUT_COOKIE_NAME}' with value "
        f"'{cookie_value}' and secure flag set to true."
    )
    response = make_response(response_body, HTTPStatus.OK)
    _set_output_cookie(response, cookie_value, path)
    return response


def init(app) -> None:

    @app.route(ROUTE_PATH, methods=["GET"])
    def benchmark_test_get():
        return _make_get_response(request.path)

    @app.route(ROUTE_PATH, methods=["POST"])
    def benchmark_test_post():
        raw_param = request.cookies.get(BENCHMARK_COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        return _make_post_response(request.path, raw_param)