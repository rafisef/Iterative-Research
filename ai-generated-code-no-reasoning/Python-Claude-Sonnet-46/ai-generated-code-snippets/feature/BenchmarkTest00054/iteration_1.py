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

_executor = concurrent.futures.ThreadPoolExecutor()


def _compute_hash_sync(input_bytes):
    hash_obj = hashlib.new('md5')
    hash_obj.update(input_bytes)
    return hash_obj.digest()


def _write_hash_sync(result):
    with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
        f.write(f'hash_value={base64.b64encode(result)}\n')


async def _compute_hash_async(input_bytes):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(_executor, _compute_hash_sync, input_bytes)
    return result


async def _write_hash_async(result):
    async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
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
        input_data = bar.read(1000)

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
        input_data = bar.read(1000)

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

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        use_async = request.args.get('async', 'false').lower() == 'true'

        if use_async:
            loop = asyncio.new_event_loop()
            try:
                RESPONSE = loop.run_until_complete(_process_request_async(param))
            finally:
                loop.close()
        else:
            RESPONSE = _process_request_sync(param)

        return RESPONSE

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
    async def BenchmarkTest00054_post_async():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        RESPONSE = await _process_request_async(param)
        return RESPONSE