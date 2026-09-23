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
import asyncio
import aiofiles
import hashlib
import base64
import io
import urllib.parse
import helpers.utils
import concurrent.futures
import os

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.environ.get('BENCHMARK_THREAD_POOL_SIZE', 10))
)

_HASH_ALGORITHM = os.environ.get('BENCHMARK_HASH_ALGORITHM', 'md5')
_PASSWORD_FILE = os.environ.get(
    'BENCHMARK_PASSWORD_FILE',
    f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'
)
_COOKIE_NAME = os.environ.get('BENCHMARK_COOKIE_NAME', 'BenchmarkTest00054')
_COOKIE_SECRET = os.environ.get('BENCHMARK_COOKIE_SECRET', 'someSecret')
_COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
_COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
_COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
_DEFAULT_ASYNC = os.environ.get('BENCHMARK_DEFAULT_ASYNC', 'false').lower() == 'true'
_INPUT_READ_LIMIT = int(os.environ.get('BENCHMARK_INPUT_READ_LIMIT', 1000))
_ROUTE_PREFIX = os.environ.get('BENCHMARK_ROUTE_PREFIX', '/benchmark/hash-00/BenchmarkTest00054')


def _compute_hash_sync(input_bytes):
    hash_obj = hashlib.new(_HASH_ALGORITHM)
    hash_obj.update(input_bytes)
    return hash_obj.digest()


def _write_hash_sync(result):
    with open(_PASSWORD_FILE, 'a') as f:
        f.write(f'hash_value={base64.b64encode(result)}\n')


async def _compute_hash_async(input_bytes):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _compute_hash_sync, input_bytes)
    return result


async def _write_hash_async(result):
    async with aiofiles.open(_PASSWORD_FILE, 'a') as f:
        await f.write(f'hash_value={base64.b64encode(result)}\n')


def _process_request_sync(param):
    RESPONSE = ""

    string26833 = ''
    copy = string26833
    string26833 = ''
    string26833 += param
    copy += 'SomeOKString'
    bar = copy

    input_data = ''
    if isinstance(bar, str):
        input_data = bar.encode('utf-8')
    elif isinstance(bar, io.IOBase):
        input_data = bar.read(_INPUT_READ_LIMIT)

    if len(input_data) == 0:
        RESPONSE += 'Cannot generate hash: Input was empty.'
        return RESPONSE

    result = _compute_hash_sync(input_data)
    _write_hash_sync(result)

    RESPONSE += (
        f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8"))}\' hashed and stored.'
    )

    return RESPONSE


async def _process_request_async(param):
    RESPONSE = ""

    string26833 = ''
    copy = string26833
    string26833 = ''
    string26833 += param
    copy += 'SomeOKString'
    bar = copy

    input_data = ''
    if isinstance(bar, str):
        input_data = bar.encode('utf-8')
    elif isinstance(bar, io.IOBase):
        input_data = bar.read(_INPUT_READ_LIMIT)

    if len(input_data) == 0:
        RESPONSE += 'Cannot generate hash: Input was empty.'
        return RESPONSE

    result = await _compute_hash_async(input_data)
    await _write_hash_async(result)

    RESPONSE += (
        f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8"))}\' hashed and stored.'
    )

    return RESPONSE


def init(app):

    @app.route(_ROUTE_PREFIX, methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            _COOKIE_NAME,
            _COOKIE_SECRET,
            max_age=_COOKIE_MAX_AGE,
            secure=_COOKIE_SECURE,
            path=request.path,
            domain=_COOKIE_DOMAIN
        )
        return response

    @app.route(_ROUTE_PREFIX, methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
        use_async = request.args.get('async', str(_DEFAULT_ASYNC)).lower() == 'true'

        if use_async:
            loop = asyncio.new_event_loop()
            try:
                RESPONSE = loop.run_until_complete(_process_request_async(param))
            finally:
                loop.close()
        else:
            RESPONSE = _process_request_sync(param)

        return RESPONSE

    @app.route(f'{_ROUTE_PREFIX}/async', methods=['POST'])
    async def BenchmarkTest00054_post_async():
        param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
        RESPONSE = await _process_request_async(param)
        return RESPONSE