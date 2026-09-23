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

ALLOWED_REDIRECT_URLS = {
    'http://localhost:5000/',
    'https://localhost:5000/',
}

def is_safe_redirect_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.netloc not in ('localhost:5000', 'localhost'):
        return False
    return url in ALLOWED_REDIRECT_URLS

def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
            max_age=60*3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        import base64

        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", ""))

        if not param:
            return redirect(url_for('BenchmarkTest00067_get'))

        tmp = base64.b64encode(param.encode('utf-8'))
        bar = base64.b64decode(tmp).decode('utf-8')

        if not is_safe_redirect_url(bar):
            return redirect(url_for('BenchmarkTest00067_get'))

        return redirect(bar)