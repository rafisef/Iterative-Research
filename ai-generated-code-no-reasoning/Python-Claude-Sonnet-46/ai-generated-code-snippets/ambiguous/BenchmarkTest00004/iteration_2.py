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

from flask import request, make_response, render_template

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00004'
COOKIE_MAX_AGE = 60 * 3
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'
NUM = 106
SAFE_VALUE = "This_should_always_happen"


def _is_safe_path(base_dir: str, target_path: str) -> bool:
    base_dir = os.path.realpath(base_dir)
    target_path = os.path.realpath(target_path)
    return os.path.commonpath([base_dir]) == os.path.commonpath([base_dir, target_path])


def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie(
            COOKIE_NAME,
            'Filename',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        param = urllib.parse.unquote_plus(raw_cookie)

        bar = SAFE_VALUE if (7 * 18 + NUM) > 200 else param

        response_parts = []

        target_path = os.path.join(helpers.utils.TESTFILES_DIR, bar)

        if not _is_safe_path(helpers.utils.TESTFILES_DIR, target_path):
            return "Invalid file path.", 400

        try:
            with codecs.open(target_path, 'r', 'utf-8') as file_target:
                safe_name = escape_for_html(os.path.basename(file_target.name))
                response_parts.append(f"Access to file: '{safe_name}' created.")
                response_parts.append("And file already exists.")
        except FileNotFoundError:
            response_parts.append("But file doesn't exist yet.")
        except (OSError, io.UnsupportedOperation):
            return "Error accessing file.", 500

        return " ".join(response_parts)