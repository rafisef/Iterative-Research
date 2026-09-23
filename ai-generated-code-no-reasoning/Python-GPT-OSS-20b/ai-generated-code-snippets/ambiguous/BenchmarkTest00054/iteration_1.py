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

from flask import make_response, request, render_template
import urllib.parse
import hashlib
import base64
import os
from helpers.utils import escape_for_html, TESTFILES_DIR

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_test_00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_test_00054_post():
        cookie_value = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00054', ''))
        data = cookie_value + 'SomeOKString'
        if not data:
            return 'Cannot generate hash: Input was empty.'
        md5_hash = hashlib.md5(data.encode('utf-8')).digest()
        file_path = os.path.join(TESTFILES_DIR, 'passwordFile.txt')
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f'hash_value={base64.b64encode(md5_hash).decode("utf-8")}\n')
        return f"Sensitive value '{escape_for_html(data)}' hashed and stored."