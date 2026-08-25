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
import hashlib
import urllib.parse

from flask import make_response, render_template, request

from helpers import utils


def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        resp = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        resp.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost',
        )
        return resp

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get('BenchmarkTest00054', 'noCookieValueSupplied')
        )
        bar = param + 'SomeOKString'
        input_bytes = bar.encode('utf-8') if isinstance(bar, str) else b''

        if not input_bytes:
            return 'Cannot generate hash: Input was empty.'

        h = hashlib.new('md5')
        h.update(input_bytes)
        digest = h.digest()

        with open(f'{utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
            f.write(f"hash_value={base64.b64encode(digest)}\n")

        return f"Sensitive value '{utils.escape_for_html(bar)}' hashed and stored."