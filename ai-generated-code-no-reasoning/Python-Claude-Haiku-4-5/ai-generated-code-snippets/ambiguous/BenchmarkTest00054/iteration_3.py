from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import hashlib
import base64
from pathlib import Path
from functools import wraps

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
HASH_ALGORITHM = 'md5'
APPEND_STRING = 'SomeOKString'

def init(app):
    def set_benchmark_cookie(response):
        response.set_cookie(
            COOKIE_CONFIG['key'],
            COOKIE_CONFIG['value'],
            max_age=COOKIE_CONFIG['max_age'],
            secure=COOKIE_CONFIG['secure'],
            path=COOKIE_CONFIG['path'],
            domain=COOKIE_CONFIG['domain'],
            httponly=COOKIE_CONFIG['httponly'],
            samesite=COOKIE_CONFIG['samesite']
        )
        return response

    @app.route(ROUTE_PATH, methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template(TEMPLATE_PATH))
        return set_benchmark_cookie(response)

    @app.route(ROUTE_PATH, methods=['POST'])
    def BenchmarkTest00054_post():
        try:
            param = urllib.parse.unquote_plus(
                request.cookies.get(COOKIE_CONFIG['key'], "noCookieValueSupplied")
            )
            bar = param + APPEND_STRING
            
            input_data = bar.encode('utf-8') if isinstance(bar, str) else bar.read(MAX_INPUT_SIZE)
            
            if not input_data:
                return 'Cannot generate hash: Input was empty.', 400
            
            result = getattr(hashlib, HASH_ALGORITHM)(input_data).digest()
            encoded_hash = base64.b64encode(result).decode()
            
            password_file = Path(TESTFILES_DIR) / 'passwordFile.txt'
            password_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(password_file, 'a') as f:
                f.write(f'hash_value={encoded_hash}\n')
            
            decoded_input = input_data.decode('utf-8')
            return f'Sensitive value \'{escape_for_html(decoded_input)}\' hashed and stored.', 200
        
        except Exception as e:
            return f'Error processing request: {escape_for_html(str(e))}', 500