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

import urllib.parse
from pathlib import Path

from flask import make_response, render_template, request

from helpers.utils import TESTFILES_DIR, escape_for_html


def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET', 'POST'])
    def BenchmarkTest00001():
        if request.method == 'GET':
            response = make_response(
                render_template('web/pathtraver-00/BenchmarkTest00001.html')
            )
            response.set_cookie(
                'BenchmarkTest00001',
                'Filename',
                max_age=180,
                secure=True,
                path=request.path,
                domain='localhost',
            )
            return response

        param = urllib.parse.unquote_plus(
            request.cookies.get('BenchmarkTest00001', 'noCookieValueSupplied')
        )
        bar = param
        file_path = Path(TESTFILES_DIR) / bar
        response = ''

        try:
            with open(file_path, encoding='utf-8') as file_target:
                response += (
                    f"Access to file: '{escape_for_html(str(file_target.name))}' created."
                )
                response += ' And file already exists.'
        except FileNotFoundError:
            response += " But file doesn't exist yet."

        return response