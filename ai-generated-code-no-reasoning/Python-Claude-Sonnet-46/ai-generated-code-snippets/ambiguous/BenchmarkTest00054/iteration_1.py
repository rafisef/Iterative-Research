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
import urllib.parse

from flask import request, make_response, render_template
import helpers.utils


def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=60 * 3,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")
        )

        bar = 'SomeOKString'

        if isinstance(bar, str):
            data = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            data = bar.read(1000)
        else:
            data = b''

        if not data:
            return 'Cannot generate hash: Input was empty.'

        digest = hashlib.md5(data).digest()

        filepath = f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'
        with open(filepath, 'a') as f:
            f.write(f'hash_value={base64.b64encode(digest).decode()}\n')

        escaped = helpers.utils.escape_for_html(data.decode('utf-8'))
        return f"Sensitive value '{escaped}' hashed and stored."