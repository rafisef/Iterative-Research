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

import hashlib
import base64
import io
import os
import urllib.parse

from flask import request, make_response, render_template
import helpers.utils

COOKIE_NAME = 'BenchmarkTest00054'
COOKIE_MAX_AGE = 60 * 3
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'


def _read_input(bar):
    if isinstance(bar, str):
        return bar.encode('utf-8')
    if isinstance(bar, io.IOBase):
        return bar.read(1000)
    return b''


def _hash_data(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _write_hash_to_file(digest: bytes) -> None:
    filepath = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
    encoded = base64.b64encode(digest).decode('utf-8')
    with open(filepath, 'a', encoding='utf-8') as f:
        f.write(f'hash_value={encoded}\n')


def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            COOKIE_NAME,
            'someSecret',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        param = urllib.parse.unquote_plus(raw_cookie)

        bar = 'SomeOKString'

        data = _read_input(bar)

        if not data:
            return 'Cannot generate hash: Input was empty.', 400

        digest = _hash_data(data)

        try:
            _write_hash_to_file(digest)
        except OSError:
            return 'Failed to store hash.', 500

        escaped = helpers.utils.escape_for_html(data.decode('utf-8'))
        return f"Sensitive value '{escaped}' hashed and stored.", 200