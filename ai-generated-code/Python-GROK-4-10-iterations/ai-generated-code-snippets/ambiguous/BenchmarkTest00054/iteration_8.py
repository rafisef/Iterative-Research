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
from pathlib import Path

from flask import make_response, render_template, request

from helpers import utils


def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET', 'POST'])
    def benchmark_test_00054():
        if request.method == 'GET':
            response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
            response.set_cookie(
                'BenchmarkTest00054',
                'someSecret',
                max_age=180,
                secure=True,
                httponly=True,
                samesite='Strict',
                path=request.path,
                domain='localhost'
            )
            return response

        param = urllib.parse.unquote_plus(
            request.cookies.get('BenchmarkTest00054', 'noCookieValueSupplied')
        )
        input_bytes = param.encode('utf-8')

        if not input_bytes:
            return 'Cannot generate hash: Input was empty.'

        digest = hashlib.sha256(input_bytes).digest()
        output_path = Path(utils.TESTFILES_DIR) / 'passwordFile.txt'

        with output_path.open('a', encoding='utf-8') as f:
            f.write(f'hash_value={base64.b64encode(digest).decode()}\n')

        escaped_param = utils.escape_for_html(param)
        return f"Sensitive value '{escaped_param}' hashed and stored."