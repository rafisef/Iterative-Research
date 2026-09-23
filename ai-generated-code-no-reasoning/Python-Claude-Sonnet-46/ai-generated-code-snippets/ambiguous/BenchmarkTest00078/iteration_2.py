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

import base64
import urllib.parse
import json

from flask import request, make_response, render_template
import helpers.utils


SAFE_COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
ALLOWED_KEYS = frozenset({'a', 'foo', 'b'})


def _safe_decode(encoded: str) -> dict:
    padded = encoded + '=' * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(padded)
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    sanitized = {k: v for k, v in data.items() if k in ALLOWED_KEYS}
    return sanitized


def init(app):

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            SAFE_COOKIE_VALUE,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        raw_cookie = request.cookies.get("BenchmarkTest00078", "")
        if not raw_cookie:
            return 'No cookie value supplied', 400

        param = urllib.parse.unquote_plus(raw_cookie)

        prefix = 'help'
        suffix = 'snapes on a plane'
        if not param.startswith(prefix) or not param.endswith(suffix):
            return 'Invalid cookie format', 400

        bar = param[len(prefix): len(param) - len(suffix)]

        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            result = _safe_decode(bar)
        except (ValueError, json.JSONDecodeError, Exception):
            return 'Decoding failed!', 400

        helpers.utils.sharedstr = str(result)

        return f'shared string is {helpers.utils.sharedstr}'