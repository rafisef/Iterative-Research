from flask import request, make_response, render_template
import helpers.utils
import hashlib
import base64
import os
from helpers.utils import escape_for_html

_FIXED_INPUT = b'SomeOKString'
_FIXED_HASH = base64.b64encode(hashlib.md5(_FIXED_INPUT).digest())
_FIXED_RESPONSE = f"Sensitive value '{escape_for_html(_FIXED_INPUT.decode())}' hashed and stored."
_HASH_LINE_ENCODED = f'hash_value={_FIXED_HASH}\n'.encode()
_PASSWORD_FILE = f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'

_cookie_config = {
    'max_age': 180,
    'secure': True,
    'domain': 'localhost'
}

_password_fd = None

def _get_password_fd():
    global _password_fd
    if _password_fd is None or _password_fd.closed:
        _password_fd = open(_PASSWORD_FILE, 'ab', buffering=0)
    return _password_fd

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            path=request.path,
            **_cookie_config)
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        _get_password_fd().write(_HASH_LINE_ENCODED)
        return _FIXED_RESPONSE