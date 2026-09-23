from flask import make_response, render_template, request, current_app
import os
import hashlib
import base64
import re
import pathlib
import secrets

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        domain = current_app.config.get('COOKIE_DOMAIN', request.host.split(':')[0])
        response.set_cookie(
            'BenchmarkTest00054',
            secrets.token_urlsafe(32),
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/benchmark/hash-00/BenchmarkTest00054',
            domain=domain
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_post():
        cookie_value = request.cookies.get('BenchmarkTest00054')
        if not cookie_value or not re.fullmatch(r'[A-Za-z0-9_-]{8,64}', cookie_value):
            return 'Invalid cookie', 400
        data = cookie_value + 'SomeOKString'
        if not isinstance(data, str):
            return 'Invalid input', 400
        data_bytes = data.encode('utf-8')
        if not data_bytes:
            return 'Cannot generate hash: Input was empty.', 400
        digest = hashlib.sha256(data_bytes).digest()
        root = pathlib.Path(current_app.root_path).resolve()
        test_dir = pathlib.Path(current_app.config.get('TESTFILES_DIR', 'data')).resolve()
        if not test_dir.is_relative_to(root):
            return 'Invalid test directory', 400
        file_path = test_dir / 'passwordFile.txt'
        file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = file_path.with_suffix('.tmp')
        with temp_path.open('wb') as f:
            f.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
        temp_path.replace(file_path)
        safe_input = data
        return f"Sensitive value '{safe_input}' hashed and stored.", 200