'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

import configparser
import urllib.parse
from http import HTTPStatus
from typing import Union

from flask import Flask, Request, Response, request, make_response, render_template

from helpers.utils import escape_for_html

COOKIE_NAME: str = 'BenchmarkTest00074'
COOKIE_VALUE: str = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
ROUTE: str = '/benchmark/codeinj-00/BenchmarkTest00074'
SECTION: str = 'section90091'
KEY_A: str = 'keyA-90091'
KEY_B: str = 'keyB-90091'
DEFAULT_COOKIE: str = 'noCookieValueSupplied'
COOKIE_MAX_AGE: int = 180
TEMPLATE_PATH: str = 'web/codeinj-00/BenchmarkTest00074.html'
COOKIE_DOMAIN: str = 'localhost'
COOKIE_SAMESITE: str = 'Strict'


def _build_config(param: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.add_section(SECTION)
    config.set(SECTION, KEY_A, 'a-Value')
    config.set(SECTION, KEY_B, param)
    return config


def _get_param_from_cookie(req: Request) -> str:
    raw_cookie = req.cookies.get(COOKIE_NAME, DEFAULT_COOKIE)
    return urllib.parse.unquote_plus(raw_cookie)


def _build_get_response(req: Request) -> Response:
    response = make_response(render_template(TEMPLATE_PATH))
    response.set_cookie(
        COOKIE_NAME,
        COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        path=req.path,
        domain=COOKIE_DOMAIN,
        httponly=True,
        samesite=COOKIE_SAMESITE,
    )
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
    config = _build_config(param)
    bar = config.get(SECTION, KEY_B)
    return _execute_bar(bar)


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00074_get() -> Response:
        return _build_get_response(request)

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00074_post() -> tuple[str, int]:
        return _build_post_response(request)