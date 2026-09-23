import urllib.parse
from http import HTTPStatus
from typing import Optional

from flask import Flask, Response, make_response, render_template, request

import helpers.utils

COOKIE_MAX_AGE: int = 180
BENCHMARK_COOKIE_NAME: str = "BenchmarkTest00064"
OUTPUT_COOKIE_NAME: str = "SomeCookie"
ROUTE_PATH: str = "/benchmark/securecookie-00/BenchmarkTest00064"
DEFAULT_COOKIE_VALUE: str = "noCookieValueSupplied"
LOCALHOST: str = "localhost"
TEMPLATE_PATH: str = "web/securecookie-00/BenchmarkTest00064.html"
SAMESITE_POLICY: str = "Strict"

_BASE_COOKIE_KWARGS: dict = {
    "secure": True,
    "httponly": True,
    "samesite": SAMESITE_POLICY,
}


def _build_cookie_kwargs(
    path: str,
    max_age: Optional[int] = None,
    domain: Optional[str] = None,
) -> dict:
    kwargs = {**_BASE_COOKIE_KWARGS, "path": path}
    if max_age is not None:
        kwargs["max_age"] = max_age
    if domain is not None:
        kwargs["domain"] = domain
    return kwargs


def _extract_cookie_value(raw_param: str) -> str:
    if not isinstance(raw_param, str):
        return ""
    decoded = urllib.parse.unquote_plus(raw_param)
    escaped = helpers.utils.escape_for_html(decoded)
    return escaped if isinstance(escaped, str) else ""


def _make_get_response(path: str) -> Response:
    response = make_response(render_template(TEMPLATE_PATH), HTTPStatus.OK)
    response.set_cookie(
        BENCHMARK_COOKIE_NAME,
        "whatever",
        **_build_cookie_kwargs(path, max_age=COOKIE_MAX_AGE, domain=LOCALHOST),
    )
    return response


def _make_post_response(path: str, raw_param: str) -> Response:
    cookie_value = _extract_cookie_value(raw_param)
    response_body = (
        f"Created cookie: '{OUTPUT_COOKIE_NAME}' with value "
        f"'{cookie_value}' and secure flag set to true."
    )
    response = make_response(response_body, HTTPStatus.OK)
    response.set_cookie(OUTPUT_COOKIE_NAME, cookie_value, **_build_cookie_kwargs(path))
    return response


def init(app: Flask) -> None:
    @app.get(ROUTE_PATH)
    def benchmark_test_get() -> Response:
        return _make_get_response(request.path)

    @app.post(ROUTE_PATH)
    def benchmark_test_post() -> Response:
        raw_param = request.cookies.get(BENCHMARK_COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        return _make_post_response(request.path, raw_param)