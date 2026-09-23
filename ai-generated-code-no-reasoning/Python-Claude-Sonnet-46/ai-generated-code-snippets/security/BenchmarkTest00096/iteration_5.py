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

from flask import request, make_response
from markupsafe import escape
import html
import re
import unicodedata

MAX_INPUT_LENGTH = 1024

def sanitize_input(value):
    if not isinstance(value, str):
        value = str(value)
    if len(value) > MAX_INPUT_LENGTH:
        value = value[:MAX_INPUT_LENGTH]
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    try:
        value = unicodedata.normalize('NFC', value)
    except (TypeError, ValueError):
        value = ''
    value = value.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    return value

def encode_output(value):
    escaped = html.escape(str(escape(value)), quote=True)
    return escaped

def init(app):

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        RESPONSE = ""

        raw_param = request.form.get("BenchmarkTest00096", "")
        if not isinstance(raw_param, str):
            raw_param = ""
        param = sanitize_input(raw_param)

        possible = "ABC"
        guess = possible[0]

        match guess:
            case 'A':
                bar = param
            case 'B':
                bar = 'bob'
            case 'C' | 'D':
                bar = param
            case _:
                bar = "bob's your uncle"

        otherarg = "static text"

        safe_bar = encode_output(bar)
        safe_otherarg = encode_output(otherarg)

        RESPONSE += (
            f"bar is '{safe_bar}' and otherarg is '{safe_otherarg}'"
        )

        response = make_response(RESPONSE)
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

        return response