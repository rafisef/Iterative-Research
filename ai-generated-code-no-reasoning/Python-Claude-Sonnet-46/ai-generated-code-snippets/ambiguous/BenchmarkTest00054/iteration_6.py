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

import base64
import hashlib
import io
import logging
import os
from http import HTTPStatus
from pathlib import Path
from typing import Union

from flask import Flask, Request, Response, make_response, render_template, request

import helpers.utils

COOKIE_NAME: str = 'BenchmarkTest00054'
COOKIE_MAX_AGE: int = 60 * 3
DEFAULT_COOKIE_VALUE: str = 'noCookieValueSupplied'
SAFE_STATIC_INPUT: str = 'SomeOKString'
MAX_READ_BYTES: int = 1000
TEMPLATE_PATH: str = 'web/hash-00/BenchmarkTest00054.html'
ROUTE: str = '/benchmark/hash-00/BenchmarkTest00054'
PASSWORD_FILE: str = 'passwordFile.txt'
HASH_ALGORITHM: str = 'sha256'

ResponseTuple = tuple[str, int]

logger = logging.getLogger(__name__)


def _read_input(bar: object) -> bytes:
    if isinstance(bar, str):
        return bar.encode('utf-8')
    if isinstance(bar, io.RawIOBase | io.BufferedIOBase):
        return bar.read(MAX_READ_BYTES) or b''
    return b''


def _hash_data(data: bytes, algorithm: str = HASH_ALGORITHM) -> bytes:
    try:
        h = hashlib.new(algorithm, data)
    except ValueError:
        logger.warning('Unsupported hash algorithm %r, falling back to sha256.', algorithm)
        h = hashlib.new('sha256', data)
    return h.digest()


def _write_hash_to_file(digest: bytes) -> None:
    filepath = Path(helpers.utils.TESTFILES_DIR) / PASSWORD_FILE
    filepath.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode(digest).decode('utf-8')
    with filepath.open('a', encoding='utf-8') as f:
        f.write(f'hash_value={encoded}\n')


def _build_cookie_response(current_request: Request) -> Response:
    response = make_response(render_template(TEMPLATE_PATH))
    response.set_cookie(
        COOKIE_NAME,
        'someSecret',
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=current_request.path,
        domain='localhost',
    )
    return response


def _process_hash_request() -> ResponseTuple:
    data = _read_input(SAFE_STATIC_INPUT)

    if not data:
        return 'Cannot generate hash: Input was empty.', HTTPStatus.BAD_REQUEST

    digest = _hash_data(data)

    try:
        _write_hash_to_file(digest)
    except OSError as exc:
        logger.error('Failed to write hash to file: %s', exc)
        return 'Failed to store hash.', HTTPStatus.INTERNAL_SERVER_ERROR

    try:
        decoded = data.decode('utf-8')
    except UnicodeDecodeError:
        decoded = data.hex()

    escaped = helpers.utils.escape_for_html(decoded)
    return f"Sensitive value '{escaped}' hashed and stored.", HTTPStatus.OK


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00054_get() -> Response:
        return _build_cookie_response(request)

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00054_post() -> ResponseTuple:
        return _process_hash_request()