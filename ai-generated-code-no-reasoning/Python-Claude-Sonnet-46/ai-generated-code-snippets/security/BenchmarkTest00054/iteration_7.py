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
import re
import logging

from flask import request, make_response, render_template, abort, session
import helpers.utils
from helpers.utils import escape_for_html

MAX_INPUT_BYTES = 1000
MAX_COOKIE_VALUE_BYTES = 4096
ALLOWED_TESTFILES_DIR = os.path.realpath(helpers.utils.TESTFILES_DIR)
PASSWORD_FILE = os.path.join(ALLOWED_TESTFILES_DIR, "passwordFile.txt")
SAFE_FILENAME_RE = re.compile(r'^[a-zA-Z0-9_\-]+\.txt$')
CSRF_TOKEN_LENGTH = 64
PBKDF2_ITERATIONS = 600000

logger = logging.getLogger(__name__)

def _safe_path(base, filename):
    resolved_base = os.path.realpath(base)
    safe_filename = os.path.basename(filename)
    if not safe_filename or safe_filename in ('.', '..'):
        raise ValueError("Invalid filename")
    if not SAFE_FILENAME_RE.match(safe_filename):
        raise ValueError("Invalid filename characters")
    full_path = os.path.realpath(os.path.join(resolved_base, safe_filename))
    if not full_path.startswith(resolved_base + os.sep) and full_path != resolved_base:
        raise ValueError("Path traversal detected")
    return full_path

def _hash_with_salt(data: bytes) -> bytes:
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac('sha256', data, salt, PBKDF2_ITERATIONS)
    return salt + dk

def _generate_csrf_token() -> str:
    return secrets.token_hex(32)

def _is_valid_csrf_token(token: str) -> bool:
    if not isinstance(token, str):
        return False
    if len(token) != CSRF_TOKEN_LENGTH:
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', token):
        return False
    return True

def _safe_encode_for_html(value: str) -> str:
    escaped = escape_for_html(value)
    return escaped

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        csrf_token = _generate_csrf_token()
        session['csrf_token_00054'] = csrf_token
        session.permanent = False
        response = make_response(render_template(
            'web/hash-00/BenchmarkTest00054.html',
            csrf_token=csrf_token
        ))
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
        csrf_form = request.form.get('csrf_token', '')
        csrf_session = session.get('csrf_token_00054', '')

        if not csrf_form or not csrf_session:
            abort(403)

        if not _is_valid_csrf_token(csrf_form) or not _is_valid_csrf_token(csrf_session):
            abort(403)

        if not hmac.compare_digest(
            csrf_session.encode('utf-8'),
            csrf_form.encode('utf-8')
        ):
            abort(403)

        session.pop('csrf_token_00054', None)

        raw_cookie = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")

        if not isinstance(raw_cookie, str):
            abort(400)

        try:
            raw_cookie_bytes = raw_cookie.encode('utf-8')
        except (UnicodeEncodeError, AttributeError):
            abort(400)

        if len(raw_cookie_bytes) > MAX_COOKIE_VALUE_BYTES:
            abort(400)

        param = urllib.parse.unquote_plus(raw_cookie)
        param = param[:MAX_INPUT_BYTES]

        bar = 'SomeOKString'

        user_input = b''
        if isinstance(bar, str):
            user_input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            user_input = bar.read(MAX_INPUT_BYTES)

        user_input = user_input[:MAX_INPUT_BYTES]

        if len(user_input) == 0:
            return 'Cannot generate hash: Input was empty.', 400

        result = _hash_with_salt(user_input)

        try:
            safe_file = _safe_path(ALLOWED_TESTFILES_DIR, "passwordFile.txt")
        except ValueError:
            return "Invalid file path.", 400

        encoded_hash = base64.b64encode(result).decode("utf-8")

        if not re.fullmatch(r'[A-Za-z0-9+/=]+', encoded_hash):
            return "Hash encoding error.", 500

        try:
            with open(safe_file, 'a') as f:
                f.write(f'hash_value={encoded_hash}\n')
        except OSError:
            logger.error("Failed to write hash to storage file.")
            return "Storage error.", 500

        try:
            decoded_input = user_input.decode('utf-8', errors='replace')
        except Exception:
            return "Encoding error.", 500

        escaped = _safe_encode_for_html(decoded_input)
        RESPONSE = f'Sensitive value \'{escaped}\' hashed and stored.'

        return RESPONSE