from flask import make_response, render_template, request, current_app
from helpers.utils import escape_for_html
import os
import hashlib
import base64

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Lax',
            path='/benchmark/hash-00/BenchmarkTest00054',
            domain=request.host.split(':')[0]
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_post():
        cookie_value = request.cookies.get('BenchmarkTest00054', 'noCookieValueSupplied')
        data = cookie_value + 'SomeOKString'
        if not isinstance(data, str):
            return 'Invalid input', 400
        data_bytes = data.encode('utf-8')
        if len(data_bytes) == 0:
            return 'Cannot generate hash: Input was empty.', 400
        hash_obj = hashlib.sha256()
        hash_obj.update(data_bytes)
        digest = hash_obj.digest()
        dir_path = current_app.config.get('TESTFILES_DIR', 'data')
        file_path = os.path.join(current_app.root_path, dir_path, 'passwordFile.txt')
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'ab') as f:
            f.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
        safe_input = escape_for_html(data_bytes.decode('utf-8', errors='replace'))
        return f"Sensitive value '{safe_input}' hashed and stored.", 200