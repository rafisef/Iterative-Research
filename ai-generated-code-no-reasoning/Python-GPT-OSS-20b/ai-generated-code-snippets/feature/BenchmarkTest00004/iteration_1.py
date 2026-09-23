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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from threading import Lock

file_lock = Lock()

def init(app):
    app.secret_key = 'super-secret-key'
    app.permanent_session_lifetime = 60 * 3

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        session.permanent = True
        session['BenchmarkTest00004'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        RESPONSE = ""
        param = session.get('BenchmarkTest00004', 'noCookieValueSupplied')
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        try:
            with file_lock:
                import codecs
                import helpers.utils
                fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')
                RESPONSE += (
                    f"Access to file: hallmark('{escape_for_html(fileTarget.name)}') created."
                )
                RESPONSE += (
                    " And file already exists."
                )
        except FileNotFoundError:
            RESPONSE += (
                " But file doesn't exist yet."
            )
        return RESPONSE