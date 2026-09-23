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

import hashlib
import base64
import io
import os
import urllib.parse
import hmac
import secrets

from flask import request, make_response, render_template, abort
import helpers.utils
from helpers.utils import escape_for_html

MAX_INPUT_BYTES = 1000
ALLOWED_TESTFILES_DIR = os.path.realpath(helpers.utils.TESTFILES_DIR)
PASSWORD_FILE = os.path.join(ALLOWED_TESTFILES_DIR, "passwordFile.txt")

def _safe_path(base, filename):
    resolved_base = os.path.realpath(base)
    full_path = os.path.realpath(os.path.join(resolved_base, os.path.basename(filename)))
    if not full_path.startswith(resolved_base + os.sep) and full_path != resolved_base:
        raise ValueError("Path traversal detected")
    return full_path

def _hash_with_salt(data: bytes) -> bytes:
    salt = secrets.token_bytes(32)
    salted = salt + data
    hash_obj = hashlib.new('sha256')
    hash_obj.update(salted)
    return salt + hash_obj.digest()

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")

        if len(raw_cookie) > MAX_INPUT_BYTES:
            abort(400)

        param = urllib.parse.unquote_plus(raw_cookie)
        param = param[:MAX_INPUT_BYTES]

        copy = 'SomeOKString'
        bar = copy

        user_input = b''
        if isinstance(bar, str):
            user_input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            user_input = bar.read(MAX_INPUT_BYTES)

        user_input = user_input[:MAX_INPUT_BYTES]

        if len(user_input) == 0:
            RESPONSE += 'Cannot generate hash: Input was empty.'
            return RESPONSE

        result = _hash_with_salt(user_input)

        try:
            safe_file = _safe_path(ALLOWED_TESTFILES_DIR, "passwordFile.txt")
        except ValueError:
            return "Invalid file path.", 400

        encoded_hash = base64.b64encode(result).decode("utf-8")

        try:
            with open(safe_file, 'a') as f:
                f.write(f'hash_value={encoded_hash}\n')
        except OSError:
            return "Storage error.", 500

        escaped = escape_for_html(user_input.decode('utf-8', errors='replace'))
        RESPONSE += f'Sensitive value \'{escaped}\' hashed and stored.'

        return RESPONSE