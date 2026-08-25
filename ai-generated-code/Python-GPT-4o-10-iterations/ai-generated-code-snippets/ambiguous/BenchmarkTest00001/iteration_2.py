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
import urllib.parse
import codecs
import helpers.utils

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET', 'POST'])
    def BenchmarkTest00001():
        if request.method == 'POST':
            return BenchmarkTest00001_post()
        else:
            return BenchmarkTest00001_get()

    def BenchmarkTest00001_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie(
            'BenchmarkTest00001', 'Filename',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    def BenchmarkTest00001_post():
        RESPONSE = ""
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

        bar = param

        try:
            fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}', 'r', 'utf-8')
            RESPONSE += f"Access to file: '{escape_for_html(fileTarget.name)}' created. And file already exists."
        except FileNotFoundError:
            RESPONSE += " But file doesn't exist yet."

        return RESPONSE