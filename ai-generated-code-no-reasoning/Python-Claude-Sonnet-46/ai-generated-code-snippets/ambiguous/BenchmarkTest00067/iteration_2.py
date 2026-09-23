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
from urllib.parse import urlparse

import flask
from flask import make_response, redirect, render_template, request

ALLOWED_HOSTS = frozenset({'localhost'})
ALLOWED_SCHEMES = frozenset({'http', 'https'})
COOKIE_NAME = 'BenchmarkTest00067'
DEFAULT_COOKIE_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
COOKIE_MAX_AGE = 60 * 3


def is_safe_redirect_url(url: str) -> bool:
    if not url:
        return False
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.netloc.split(':')[0].lower()
        return parsed.scheme in ALLOWED_SCHEMES and host in ALLOWED_HOSTS
    except ValueError:
        return False


def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            COOKIE_NAME,
            DEFAULT_COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost',
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        bar = urllib.parse.unquote_plus(raw_cookie)

        if not is_safe_redirect_url(bar):
            flask.abort(400)

        return redirect(bar, code=302)