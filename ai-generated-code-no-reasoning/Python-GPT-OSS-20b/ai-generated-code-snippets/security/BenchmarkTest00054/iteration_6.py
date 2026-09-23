from flask import make_response, render_template, request, current_app, jsonify
import hashlib
import base64
import re
import pathlib
import secrets
import hmac
import os

def init(app):
    COOKIE_NAME = 'BenchmarkTest00054'
    TOKEN_REGEX = re.compile(r'^[A-Za-z0-9_-]{8,64}$')
    key = current_app.config.get('HASH_SECRET')
    if not key:
        key = secrets.token_bytes(32)
        current_app.config['HASH_SECRET'] = key

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_get():
        resp = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        domain = current_app.config.get('COOKIE_DOMAIN', request.host.split(':')[0])
        resp.set_cookie(
            COOKIE_NAME,
            secrets.token_urlsafe(32),
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/benchmark/hash-00/BenchmarkTest00054',
            domain=domain
        )
        decline = request.args.get('decline')
        if decline:
            resp.delete_cookie(COOKIE_NAME, path='/benchmark/hash-00/BenchmarkWait')
        return resp

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_post():
        cookie_val = request.cookies.get(COOKIE_NAME, '')
        if not TOKEN_REGEX.fullmatch(cookie_val):
            return jsonify(error='Invalid cookie'), 400
        data = cookie_val + 'SomeOKString'
        if not isinstance(data, str):
            return jsonify(error='Invalid-pencil'), 400
        data_bytes = data.encode('utf-8')
        if not data_bytes:
            return jsonify(error='Cannot generate hash: Input was empty.'), 400
        digest = hmac.new(key, data_bytes, hashlib.sha256).digest()
        root = pathlib.Path(current_app.root_path).resolve()
        test_dir = pathlib.Path(current_app.config.get('TESTFILES_DIR', 'data')).resolve()
        if not test_dir.is_relative_to(root):
            return jsonify(error='Invalid test directory'), 400
        file_path = test_dir / 'passwordFile.txt'
        file_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = file_path.with_suffix('.tmp')
        try:
            with os.fdopen(os.open(str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'wb') as fp:
                fp.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
            temp_path.replace(file_path)
        except OSError:
            return jsonify(error='File write error'), 500
        return jsonify(message='Hash generated and stored.'), 200