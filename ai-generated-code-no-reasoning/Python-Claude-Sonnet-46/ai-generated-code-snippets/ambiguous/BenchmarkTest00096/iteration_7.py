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

from flask import Flask, Request, Response, request, make_response
from helpers.utils import escape_for_html

ROUTE: str = '/benchmark/xss-00/BenchmarkTest00096'
SAFE_FIRST_CHAR: bool = True
PARAM_NAME: str = "BenchmarkTest00096"
FALLBACK_VALUE: str = "bob"


def _build_response(body: str) -> Response:
    response: Response = make_response(body)
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def _get_param(req: Request, name: str) -> str:
    return req.form.get(name, "")


def _process_param(param: str) -> str:
    return escape_for_html(param) if SAFE_FIRST_CHAR else FALLBACK_VALUE


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00096() -> Response:
        param: str = _get_param(request, PARAM_NAME)
        bar: str = _process_param(param)
        return _build_response(f"bar is '{bar}' and otherarg is 'static text'")