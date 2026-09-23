from flask import Flask, request, current_app, jsonify, make_response, render_template, abort
import hashlib
import base64
import pathlib
import secrets
import hmac
import os
import re
import tempfile

COOKIE_NAME = 'BenchmarkTest00054'
TOKEN_REGEX = re.compile(r'^[A-Za-z0-9_-]{8,64}$')

def init(app: Flask):
    key = current_app.config.get('HASH_SECRET')
    if not isinstance(key, bytes):
        key = secrets.token_bytes(32)
        current_app.config['HASH_SECRET'] = key

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_get():
        resp = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        domain = current_app.config.get('COOKIE_DOMAIN') or request.host.split(':')[0]
        cookie_value = secrets.token_urlsafe(32)
        resp.set_cookie(
            COOKIE_NAME,
            cookie_value,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/benchmark/hash-00/BenchmarkTest00054',
            domain=domain
        )
        if request.args.get('decline'):
            resp.delete_cookie(COOKIE_NAME, path='/benchmark/hash-00/BenchmarkTest00054')
        return resp

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_post():
        cookie_val = request.cookies.get(COOKIE_NAME)
        if not cookie_val or not TOKEN_REGEX.fullmatch(cookie_val):
            abort(400, description='Invalid cookie')
        csrf_token = request.headers.get('X-CSRF-Token', '')
        if not csrf_token or not hmac.compare_digest(csrf_token, cookie_val):
            abort(400, description='CSRF token missing or invalid')
        data_bytes = (cookie_val + 'SomeOKString').encode('utf-8')
        if not data_bytes:
            abort(400, description='Cannot generate hash: Input was empty.')
        digest = hmac.new(key, data_bytes, hashlib.sha256).digest()
        root = pathlib.Path(current_app.root_path).resolve()
        test_dir = pathlib.Path(current_app.config.get('TESTFILES_DIR', 'data')).resolve()
        if not test_dir.is_relative_to(root):
            abort(400, description='Invalid test directory')
        file_path = test_dir / 'passwordFile.txt'
        try:
            test_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.NamedTemporaryFile(
                dir=str(test_dir), prefix='tmp', suffix='.txt', delete=False, mode='wb', dirmode=0o700, filemode=0o600
            ) as tmp:
                tmp.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
                tmp_path = pathlib.Path(tmp.name)
            os.replace(tmp_path, file_path)
        except OSError:
            abort(500, description='File write error')
        return jsonify(message='Hash generated and stored.'), 200