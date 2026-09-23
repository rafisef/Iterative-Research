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

import codecs
import io
import os
import urllib.parse
from pathlib import Path
from typing import Union

from flask import Flask, Response, request, make_response, render_template

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME: str = 'BenchmarkTest00004'
COOKIE_MAX_AGE: int = 60 * 3
DEFAULT_COOKIE_VALUE: str = 'noCookieValueSupplied'
SAFE_VALUE: str = "This_should_always_happen"
_ROUTE: str = '/benchmark/pathtraver-00/BenchmarkTest00004'
_SAFE_CONDITION: bool = (7 * 18 + 106) > 200

_TESTFILES_BASE: Path = Path(helpers.utils.TESTFILES_DIR).resolve()


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    return base_dir == target_path or base_dir in target_path.parents


def _build_cookie_response() -> Response:
    response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
    response.set_cookie(
        COOKIE_NAME,
        'Filename',
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=_ROUTE,
        domain='localhost',
    )
    return response


def _resolve_param() -> str:
    raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    param = urllib.parse.unquote_plus(raw_cookie)
    return SAFE_VALUE if _SAFE_CONDITION else param


def _sanitize_filename(filename: str) -> str:
    return os.path.basename(filename).strip()


def _read_file(target_path: Path) -> tuple[list[str], Union[tuple[str, int], None]]:
    response_parts: list[str] = []
    try:
        with codecs.open(str(target_path), 'r', 'utf-8') as file_target:
            safe_name = escape_for_html(os.path.basename(file_target.name))
            response_parts.append(f"Access to file: '{safe_name}' created.")
            response_parts.append("And file already exists.")
    except FileNotFoundError:
        response_parts.append("But file doesn't exist yet.")
    except (OSError, io.UnsupportedOperation):
        return [], ("Error accessing file.", 500)
    return response_parts, None


def init(app: Flask) -> None:

    @app.route(_ROUTE, methods=['GET'])
    def BenchmarkTest00004_get() -> Response:
        return _build_cookie_response()

    @app.route(_ROUTE, methods=['POST'])
    def BenchmarkTest00004_post() -> Union[Response, tuple[str, int]]:
        bar = _resolve_param()
        sanitized_bar = _sanitize_filename(bar)

        if not sanitized_bar:
            return "Invalid file path.", 400

        target_path = (_TESTFILES_BASE / sanitized_bar).resolve()

        if not _is_safe_path(_TESTFILES_BASE, target_path):
            return "Invalid file path.", 400

        response_parts, error = _read_file(target_path)
        if error:
            return error

        return " ".join(response_parts)