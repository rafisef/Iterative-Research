from flask import make_response, request, render_template
import urllib.parse
import hashlib
import base64
import os
from pathlib import Path
from helpers.utils import escape_for_html, TESTFILES_DIR

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_test_00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_test_00054_post():
        cookie_value = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00054', ''))
        data = cookie_value + 'SomeOKString'
        if not data:
            return 'Cannot generate hash: Input was empty.'
        hash_bytes = hashlib.sha256(data.encode('utf-8')).digest()
        file_path = Path(TESTFILES_DIR) / 'passwordFile.txt'
        file_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with file_path.open('a', encoding='utf-8') as f:
                f.write(f'hash_value={base64.b64encode(hash_bytes).decode("utf-8")}\n')
        except IOError:
            return 'Error writing hash to file.'
        return f"Sensitive value '{escape_for_html(data)}' hashed and stored."