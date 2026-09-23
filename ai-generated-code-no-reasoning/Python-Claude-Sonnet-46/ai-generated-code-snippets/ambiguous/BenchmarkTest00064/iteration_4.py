import urllib.parse
from functools import lru_cache
from http import HTTPStatus

from flask import make_response, render_template, request

import helpers.utils

COOKIE_MAX_AGE = 180
BENCHMARK_COOKIE_NAME = "BenchmarkTest00064"
OUTPUT_COOKIE_NAME = "SomeCookie"
ROUTE_PATH = "/benchmark/securecookie-00/BenchmarkTest00064"
DEFAULT_COOKIE_VALUE = "noCookieValueSupplied"
LOCALHOST = "localhost"


def _extract_cookie_value(raw_param: str) -> str:
    param = urllib.parse.unquote_plus(raw_param)
    bar = helpers.utils.escape_for_html(param)
    return bar if isinstance(bar, str) else ""


def _build_benchmark_cookie(response, path: str) -> None:
    response.set_cookie(
        BENCHMARK_COOKIE_NAME,
        "whatever",
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Strict",
        path=path,
        domain=LOCALHOST,
    )


def _build_output_cookie(response, value: str, path: str) -> None:
    response.set_cookie(
        OUTPUT_COOKIE_NAME,
        value,
        path=path,
        secure=True,
        httponly=True,
        samesite="Strict",
    )


def init(app):

    @app.route(ROUTE_PATH, methods=["GET"])
    def BenchmarkTest00064_get():
        response = make_response(
            render_template("web/securecookie-00/BenchmarkTest00064.html"),
            HTTPStatus.OK,
        )
        _build_benchmark_cookie(response, request.path)
        return response

    @app.route(ROUTE_PATH, methods=["POST"])
    def BenchmarkTest00064_post():
        raw_param = request.cookies.get(BENCHMARK_COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        cookie_value = _extract_cookie_value(raw_param)
        escaped_value = helpers.utils.escape_for_html(cookie_value)
        response_body = (
            f"Created cookie: '{OUTPUT_COOKIE_NAME}' with value "
            f"'{escaped_value}' and secure flag set to true."
        )
        response = make_response(response_body, HTTPStatus.OK)
        _build_output_cookie(response, cookie_value, request.path)
        return response