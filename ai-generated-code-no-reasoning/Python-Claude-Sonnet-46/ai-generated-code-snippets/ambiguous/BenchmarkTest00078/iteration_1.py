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

import pickle
import base64
import urllib.parse

from flask import request, make_response, render_template
import helpers.utils


def init(app):

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
            max_age=60 * 3,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00078", "noCookieValueSupplied")
        )

        string9895 = 'help' + param + 'snapes on a plane'
        bar = string9895[4:-17]

        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            padded = bar + '=' * (-len(bar) % 4)
            unpickled = pickle.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return 'Unpickling failed!'

        return f'shared string is {helpers.utils.sharedstr}'