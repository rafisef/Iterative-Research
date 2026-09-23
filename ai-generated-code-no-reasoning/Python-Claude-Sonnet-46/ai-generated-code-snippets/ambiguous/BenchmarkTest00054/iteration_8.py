import base64
import hashlib
import io
import logging
import os
import secrets
from http import HTTPStatus
from pathlib import Path

from flask import Flask, Request, Response, make_response, render_template, request

import helpers.utils

COOKIE_NAME: str = 'BenchmarkTest00054'
COOKIE_MAX_AGE: int = 180
DEFAULT_COOKIE_VALUE: str = 'noCookieValueSupplied'
SAFE_STATIC_INPUT: str = 'SomeOKString'
MAX_READ_BYTES: int = 1000
TEMPLATE_PATH: str = 'web/hash-00/BenchmarkTest00054.html'
ROUTE: str = '/benchmark/hash-00/BenchmarkTest00054'
PASSWORD_FILE: str = 'passwordFile.txt'
HASH_ALGORITHM: str = 'sha256'
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(hashlib.algorithms_guaranteed)

ResponseTuple = tuple[str, int]

logger = logging.getLogger(__name__)


def _read_input(bar: object) -> bytes:
    if isinstance(bar, str):
        return bar.encode('utf-8')
    if isinstance(bar, (io.RawIOBase, io.BufferedIOBase)):
        data = bar.read(MAX_READ_BYTES)
        return data if data else b''
    return b''


def _hash_data(data: bytes, algorithm: str = HASH_ALGORITHM) -> bytes:
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        logger.warning('Unsupported hash algorithm %r, falling back to sha256.', algorithm)
        algorithm = 'sha256'
    return hashlib.new(algorithm, data).digest()


def _write_hash_to_file(digest: bytes) -> None:
    filepath = Path(helpers.utils.TESTFILES_DIR) / PASSWORD_FILE
    filepath.parent.mkdir(parents=True, exist_ok=True)
    encoded = base64.b64encode(digest).decode('utf-8')
    entry = f'hash_value={encoded}\n'
    tmp_path = filepath.with_suffix('.tmp')
    try:
        with tmp_path.open('w', encoding='utf-8') as f:
            f.write(entry)
            f.flush()
            os.fsync(f.fileno())
        if filepath.exists():
            with filepath.open('a', encoding='utf-8') as f:
                f.write(entry)
            tmp_path.unlink(missing_ok=True)
        else:
            tmp_path.replace(filepath)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise


def _build_cookie_response(current_request: Request) -> Response:
    response = make_response(render_template(TEMPLATE_PATH))
    response.set_cookie(
        COOKIE_NAME,
        secrets.token_hex(32),
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