import configparser
import urllib.parse
from http import HTTPStatus
from typing import Final

from flask import Flask, Request, Response, request, make_response, render_template

from helpers.utils import escape_for_html

COOKIE_NAME: Final[str] = 'BenchmarkTest00074'
COOKIE_VALUE: Final[str] = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
ROUTE: Final[str] = '/benchmark/codeinj-00/BenchmarkTest00074'
SECTION: Final[str] = 'section90091'
KEY_A: Final[str] = 'keyA-90091'
KEY_B: Final[str] = 'keyB-90091'
KEY_A_VALUE: Final[str] = 'a-Value'
DEFAULT_COOKIE: Final[str] = 'noCookieValueSupplied'
COOKIE_MAX_AGE: Final[int] = 180
TEMPLATE_PATH: Final[str] = 'web/codeinj-00/BenchmarkTest00074.html'
COOKIE_DOMAIN: Final[str] = 'localhost'
COOKIE_SAMESITE: Final[str] = 'Strict'


def _build_config(param: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.add_section(SECTION)
    config.set(SECTION, KEY_A, KEY_A_VALUE)
    config.set(SECTION, KEY_B, param)
    return config


def _get_param_from_cookie(req: Request) -> str:
    return urllib.parse.unquote_plus(req.cookies.get(COOKIE_NAME, DEFAULT_COOKIE))


def _set_response_cookie(response: Response, path: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        path=path,
        domain=COOKIE_DOMAIN,
        httponly=True,
        samesite=COOKIE_SAMESITE,
    )


def _build_get_response(req: Request) -> Response:
    response = make_response(render_template(TEMPLATE_PATH))
    _set_response_cookie(response, req.path)
    return response


def _execute_bar(bar: str) -> tuple[str, int]:
    try:
        exec(bar)  # noqa: S102
        return '', HTTPStatus.OK
    except Exception:
        return (
            f"Error executing statement '{escape_for_html(bar)}'",
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )


def _build_post_response(req: Request) -> tuple[str, int]:
    param = _get_param_from_cookie(req)
    bar = _build_config(param).get(SECTION, KEY_B)
    return _execute_bar(bar)


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00074_get() -> Response:
        return _build_get_response(request)

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00074_post() -> tuple[str, int]:
        return _build_post_response(request)