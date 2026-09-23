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

from flask import request, make_response, render_template
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00074'
COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
ROUTE = '/benchmark/codeinj-00/BenchmarkTest00074'
SECTION = 'section90091'
KEY_A = 'keyA-90091'
KEY_B = 'keyB-90091'
DEFAULT_COOKIE = 'noCookieValueSupplied'
COOKIE_MAX_AGE = 180


def _build_config(param: str) -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.add_section(SECTION)
    config.set(SECTION, KEY_A, 'a-Value')
    config.set(SECTION, KEY_B, param)
    return config


def _get_param_from_cookie() -> str:
    raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE)
    return urllib.parse.unquote_plus(raw_cookie)


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00074_post():
        param = _get_param_from_cookie()
        config = _build_config(param)
        bar = config.get(SECTION, KEY_B)

        try:
            exec(bar)
            return ""
        except Exception:
            return f"Error executing statement '{escape_for_html(bar)}'"