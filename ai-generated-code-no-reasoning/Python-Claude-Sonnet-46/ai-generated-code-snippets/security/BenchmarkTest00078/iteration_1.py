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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import json
import re
import urllib.parse
import base64
import helpers.utils

SAFE_COOKIE_PATTERN = re.compile(r'^[A-Za-z0-9+/=_-]{1,512}$')

ALLOWED_DATA = {
    'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
}

def _safe_decode_cookie(raw_value: str) -> dict:
    if not SAFE_COOKIE_PATTERN.match(raw_value):
        raise ValueError("Cookie contains invalid characters")
    decoded_bytes = base64.urlsafe_b64decode(raw_value + '==')
    data = json.loads(decoded_bytes.decode('utf-8', errors='strict'))
    if not isinstance(data, dict):
        raise ValueError("Unexpected data structure")
    return data

def init(app):

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            'eyJBIjogImZvbyIsICJCIjogOTl9',
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
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00078", "")

        if not raw_cookie:
            return "No cookie value supplied", 400

        raw_cookie = urllib.parse.unquote_plus(raw_cookie)

        if not SAFE_COOKIE_PATTERN.match(raw_cookie):
            return "Invalid cookie format", 400

        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            data = _safe_decode_cookie(raw_cookie)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, Exception):
            RESPONSE += 'Deserialization failed!'
            return RESPONSE, 400

        RESPONSE += escape_for_html(
            f'shared string is {helpers.utils.sharedstr}'
        )

        return RESPONSE