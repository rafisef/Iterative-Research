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
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
_HASH_ITERATIONS = int(os.environ.get('BENCHMARK_HASH_ITERATIONS', 1))
_WRITE_TIMEOUT = float(os.environ.get('BENCHMARK_WRITE_TIMEOUT', 5.0))
_RETRY_ATTEMPTS = int(os.environ.get('BENCHMARK_RETRY_ATTEMPTS', 3))
_RETRY_DELAY = float(os.environ.get('BENCHMARK_RETRY_DELAY', 0.1))

_file_lock = threading.Lock()
_async_file_lock = asyncio.Lock() if False else None


def _get_async_lock():
    global _async_file_lock
    if _async_file_lock is None:
        _async_file_lock = asyncio.Lock()
    return _async_file_lock


def _validate_algorithm(algorithm):
    available = hashlib.algorithms_available
    if algorithm not in available:
        raise ValueError(f'Hash algorithm {algorithm!r} is not available. Choose from: {sorted(available)}')
    return algorithm


def _compute_hash_sync(input_bytes, algorithm=None):
    algo = algorithm or _HASH_ALGORITHM
    _validate_algorithm(algo)
    hash_obj = hashlib.new(algo)
    for _ in range(_HASH_ITERATIONS):
        hash_obj.update(input_bytes)
    return hash_obj.digest()


def _write_hash_sync(result, filepath=None, retries=None):
    target_file = filepath or _PASSWORD_FILE
    attempts = retries if retries is not None else _RETRY_ATTEMPTS
    last_exc = None
    for attempt in range(attempts):
        try:
            with _file_lock:
                with open(target_file, 'a') as f:
                    f.write(f'hash_value={base64.b64encode(result).decode("utf-8")}\n')
                    f.flush()
                    os.fsync(f.fileno())
            return
        except OSError as exc:
            last_exc = exc
            logger.warning(f'Write attempt {attempt + 1}/{attempts} failed: {exc}')
            if attempt < attempts - 1:
                time.sleep(_RETRY_DELAY * (attempt + 1))
    raise IOError(f'Failed to write hash after {attempts} attempts') from last_exc


async def _compute_hash_async(input_bytes, algorithm=None):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        _executor,
        lambda: _compute_hash_sync(input_bytes, algorithm)
    )
    return result


async def _write_hash_async(result, filepath=None, retries=None):
    target_file = filepath or _PASSWORD_FILE
    attempts = retries if retries is not None else _RETRY_ATTEMPTS
    last_exc = None

    try:
        lock = _get_async_lock()
    except RuntimeError:
        loop = asyncio.get_event_loop()
        result_future = loop.run_in_executor(
            _executor,
            lambda: _write_hash_sync(result, filepath, retries)
        )
        await result_future
        return

    for attempt in range(attempts):
        try:
            async with lock:
                async with aiofiles.open(target_file, 'a') as f:
                    await f.write(f'hash_value={base64.b64encode(result).decode("utf-8")}\n')
                    await f.flush()
            return
        except OSError as exc:
            last_exc = exc
            logger.warning(f'Async write attempt {attempt + 1}/{attempts} failed: {exc}')
            if attempt < attempts - 1:
                await asyncio.sleep(_RETRY_DELAY * (attempt + 1))
    raise IOError(f'Failed to write hash after {attempts} attempts') from last_exc


def _extract_input_data(bar):
    if isinstance(bar, bytes):
        return bar[:_INPUT_READ_LIMIT]
    elif isinstance(bar, str):
        return bar.encode('utf-8')[:_INPUT_READ_LIMIT]
    elif isinstance(bar, io.IOBase):
        return bar.read(_INPUT_READ_LIMIT)
    elif isinstance(bar, (bytearray, memoryview)):
        return bytes(bar)[:_INPUT_READ_LIMIT]
    return b''


def _build_param_string(param):
    string26833 = ''
    copy = string26833
    string26833 = ''
    string26833 += param
    copy += 'SomeOKString'
    bar = copy
    return bar


def _process_request_sync(param, algorithm=None):
    RESPONSE = ""

    bar = _build_param_string(param)
    input_data = _extract_input_data(bar)

    if len(input_data) == 0:
        RESPONSE += 'Cannot generate hash: Input was empty.'
        return RESPONSE

    try:
        result = _compute_hash_sync(input_data, algorithm)
        _write_hash_sync(result)
        RESPONSE += (
            f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8", errors="replace"))}\' hashed and stored.'
        )
    except ValueError as exc:
        RESPONSE += f'Hash computation error: {exc}'
    except IOError as exc:
        RESPONSE += f'Storage error: {exc}'

    return RESPONSE


async def _process_request_async(param, algorithm=None):
    RESPONSE = ""

    bar = _build_param_string(param)
    input_data = _extract_input_data(bar)

    if len(input_data) == 0:
        RESPONSE += 'Cannot generate hash: Input was empty.'
        return RESPONSE

    try:
        result = await _compute_hash_async(input_data, algorithm)
        await _write_hash_async(result)
        RESPONSE += (
            f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8", errors="replace"))}\' hashed and stored.'
        )
    except ValueError as exc:
        RESPONSE += f'Hash computation error: {exc}'
    except IOError as exc:
        RESPONSE += f'Storage error: {exc}'

    return RESPONSE


async def _process_request_async_with_timeout(param, algorithm=None, timeout=None):
    effective_timeout = timeout or _WRITE_TIMEOUT
    try:
        result = await asyncio.wait_for(
            _process_request_async(param, algorithm),
            timeout=effective_timeout
        )
        return result
    except asyncio.TimeoutError:
        return f'Request timed out after {effective_timeout} seconds.'


def _run_async_in_thread(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        finally:
            loop.close()


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
        algorithm = request.args.get('algorithm', _HASH_ALGORITHM)
        timeout = request.args.get('timeout', None)
        if timeout is not None:
            try:
                timeout = float(timeout)
            except ValueError:
                timeout = None

        if use_async:
            if timeout is not None:
                coro = _process_request_async_with_timeout(param, algorithm, timeout)
            else:
                coro = _process_request_async(param, algorithm)
            RESPONSE = _run_async_in_thread(coro)
        else:
            RESPONSE = _process_request_sync(param, algorithm)

        return RESPONSE

    @app.route(f'{_ROUTE_PREFIX}/async', methods=['POST'])
    async def BenchmarkTest00054_post_async():
        param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
        algorithm = request.args.get('algorithm', _HASH_ALGORITHM)
        timeout = request.args.get('timeout', None)
        if timeout is not None:
            try:
                timeout = float(timeout)
            except ValueError:
                timeout = None

        if timeout is not None:
            RESPONSE = await _process_request_async_with_timeout(param, algorithm, timeout)
        else:
            RESPONSE = await _process_request_async(param, algorithm)
        return RESPONSE

    @app.route(f'{_ROUTE_PREFIX}/sync', methods=['POST'])
    def BenchmarkTest00054_post_sync():
        param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
        algorithm = request.args.get('algorithm', _HASH_ALGORITHM)
        RESPONSE = _process_request_sync(param, algorithm)
        return RESPONSE

    @app.route(f'{_ROUTE_PREFIX}/batch', methods=['POST'])
    def BenchmarkTest00054_post_batch():
        params = request.json if request.is_json else {}
        items = params.get('items', [])
        algorithm = params.get('algorithm', _HASH_ALGORITHM)
        use_async = params.get('async', _DEFAULT_ASYNC)

        if not isinstance(items, list):
            return 'Invalid input: expected a list of items.', 400

        results = []

        if use_async:
            async def process_all():
                tasks = [_process_request_async(str(item), algorithm) for item in items]
                return await asyncio.gather(*tasks, return_exceptions=True)

            raw_results = _run_async_in_thread(process_all())
            for r in raw_results:
                if isinstance(r, Exception):
                    results.append(f'Error: {r}')
                else:
                    results.append(r)
        else:
            for item in items:
                try:
                    results.append(_process_request_sync(str(item), algorithm))
                except Exception as exc:
                    results.append(f'Error: {exc}')

        return '\n'.join(results)

    @app.route(f'{_ROUTE_PREFIX}/stream', methods=['POST'])
    async def BenchmarkTest00054_post_stream():
        param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
        algorithm = request.args.get('algorithm', _HASH_ALGORITHM)
        chunk_size = int(request.args.get('chunk_size', 64))

        bar = _build_param_string(param)
        input_data = _extract_input_data(bar)

        if len(input_data) == 0:
            return 'Cannot generate hash: Input was empty.'

        try:
            _validate_algorithm(algorithm)
        except ValueError as exc:
            return f'Hash computation error: {exc}'

        hash_obj = hashlib.new(algorithm)
        chunks = [input_data[i:i + chunk_size] for i in range(0, len(input_data), chunk_size)]

        loop = asyncio.get_event_loop()

        def update_hash():
            for chunk in chunks:
                hash_obj.update(chunk)
            return hash_obj.digest()

        result = await loop.run_in_executor(_executor, update_hash)
        await _write_hash_async(result)

        return (
            f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8", errors="replace"))}\' '
            f'hashed in {len(chunks)} chunk(s) and stored.'
        )