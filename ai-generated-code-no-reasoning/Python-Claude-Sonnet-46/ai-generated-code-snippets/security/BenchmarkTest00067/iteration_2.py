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
import hmac
import hashlib
import os
import re

ALLOWED_REDIRECT_URLS = frozenset({
    'http://localhost:5000/',
    'https://localhost:5000/',
})

ALLOWED_HOSTS = frozenset({'localhost:5000', 'localhost'})
ALLOWED_SCHEMES = frozenset({'http', 'https'})
COOKIE_SECRET = os.environ.get('COOKIE_SECRET', os.urandom(32))

def _sign_value(value: str) -> str:
    mac = hmac.new(
        COOKIE_SECRET if isinstance(COOKIE_SECRET, bytes) else COOKIE_SECRET.encode(),
        value.encode('utf-8'),
        hashlib.sha256
    )
    return mac.hexdigest()

def _verify_signed_cookie(value: str, signature: str) -> bool:
    expected = _sign_value(value)
    return hmac.compare_digest(expected, signature)

def is_safe_redirect_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    if len(url) > 256:
        return False
    if not url in ALLOWED_REDIRECT_URLS:
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    if parsed.netloc not in ALLOWED_HOSTS:
        return False
    if parsed.path not in ('/', ''):
        return False
    if parsed.query or parsed.fragment or parsed.params:
        return False
    return True

def _sanitize_cookie_value(raw: str) -> str:
    return re.sub(r'[^\x20-\x7E]', '', raw)

def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        cookie_value = 'http%3A%2F%2Flocalhost%3A5000%2F'
        signature = _sign_value(cookie_value)
        response.set_cookie(
            'BenchmarkTest00067',
            cookie_value,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        response.set_cookie(
            'BenchmarkTest00067_sig',
            signature,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        raw_cookie = request.cookies.get('BenchmarkTest00067', '')
        raw_sig = request.cookies.get('BenchmarkTest00067_sig', '')

        if not raw_cookie or not raw_sig:
            return redirect(url_for('BenchmarkTest00067_get'))

        raw_cookie = _sanitize_cookie_value(raw_cookie)
        raw_sig = _sanitize_cookie_value(raw_sig)

        if not _verify_signed_cookie(raw_cookie, raw_sig):
            return redirect(url_for('BenchmarkTest00067_get'))

        param = urllib.parse.unquote_plus(raw_cookie)

        if not param:
            return redirect(url_for('BenchmarkTest00067_get'))

        if not is_safe_redirect_url(param):
            return redirect(url_for('BenchmarkTest00067_get'))

        return redirect(param, code=302)