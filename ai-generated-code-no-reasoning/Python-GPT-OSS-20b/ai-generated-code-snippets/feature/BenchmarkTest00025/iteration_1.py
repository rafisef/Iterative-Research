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

import os
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):
    cookie_domain = os.getenv('BENCHMARK_COOKIE_DOMAIN', 'localhost')
    cookie_max_age = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', 60*3))
    secure_flag = os.getenv('BENCHMARK_COOKIE_SECURE', 'True').lower() in ('true', '1', 'yes')

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
                            max_age=cookie_max_age,
                            secure=secure_flag,
                            path=request.path,
                            domain=cookie_domain)
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ""
        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))
        superstring = f'90583{param}abcd'
        bar = superstring[len('90583'):len(superstring)-5]
        import random
        from helpers.utils import mysession
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]
        if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
            RESPONSE += f'Welcome back: {user}<br/>'
        else:
            mysession[cookie] = value
            RESPONSE += (f'{user} has been remembered with cookie: '
                         f'{cookie} whose value is: {mysession[cookie]}<br/>')
        return RESPONSE