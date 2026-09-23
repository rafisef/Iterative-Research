from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import hashlib
import base64
from pathlib import Path
from functools import wraps
from typing import Tuple, Optional
import logging

logger = logging.getLogger(__name__)

COOKIE_CONFIG = {
    'key': 'BenchmarkTest00054',
    'value': 'someSecret',
    'max_age': 180,
    'secure': True,
    'path': '/benchmark/hash-00/BenchmarkTest00054',
    'domain': 'localhost',
    'httponly': True,
    'samesite': 'Strict'
}

ROUTE_PATH = '/benchmark/hash-00/BenchmarkTest00054'
TEMPLATE_PATH = 'web/hash-00/BenchmarkTest00054.html'
MAX_INPUT_SIZE = 1000
HASH_ALGORITHM = 'sha256'
APPEND_STRING = 'SomeOKString'
PASSWORD_FILE = Path(TESTFILES_DIR) / 'passwordFile.txt'


def _set_benchmark_cookie(response):
    response.set_cookie(**COOKIE_CONFIG)
    return response


def _encode_to_bytes(data: str | bytes) -> bytes:
    if isinstance(data, str):
        return data.encode('utf-8')
    if hasattr(data, 'read'):
        return data.read(MAX_INPUT_SIZE)
    return data


def _hash_and_store(input_data: bytes) -> Tuple[Optional[str], Optional[str]]:
    if not input_data:
        return None, 'Cannot generate hash: Input was empty.'
    
    try:
        result = hashlib.new(HASH_ALGORITHM, input_data).digest()
    except ValueError as e:
        logger.error(f'Invalid hash algorithm: {HASH_ALGORITHM}', exc_info=True)
        return None, f'Invalid hash algorithm: {HASH_ALGORITHM}'
    
    encoded_hash = base64.b64encode(result).decode('utf-8')
    
    try:
        PASSWORD_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PASSWORD_FILE, 'a', encoding='utf-8') as f:
            f.write(f'hash_value={encoded_hash}\n')
    except IOError as e:
        logger.error(f'Failed to write hash to file: {PASSWORD_FILE}', exc_info=True)
        return None, 'Failed to store hash'
    
    return encoded_hash, None


def init(app):
    @app.route(ROUTE_PATH, methods=['GET', 'POST'])
    def benchmark_test():
        if request.method == 'GET':
            response = make_response(render_template(TEMPLATE_PATH))
            return _set_benchmark_cookie(response)
        
        try:
            param = urllib.parse.unquote_plus(
                request.cookies.get(COOKIE_CONFIG['key'], 'noCookieValueSupplied')
            )
            bar = param + APPEND_STRING
            
            input_data = _encode_to_bytes(bar)
            
            encoded_hash, error = _hash_and_store(input_data)
            if error:
                return error, 400
            
            decoded_input = input_data.decode('utf-8')
            return f'Sensitive value \'{escape_for_html(decoded_input)}\' hashed and stored.', 200
        
        except UnicodeDecodeError as e:
            logger.warning(f'Unicode decode error: {e}', exc_info=True)
            return f'Error decoding input: {escape_for_html(str(e))}', 400
        except Exception as e:
            logger.exception(f'Unexpected error processing request: {e}')
            return f'Error processing request: {escape_for_html(str(e))}', 500