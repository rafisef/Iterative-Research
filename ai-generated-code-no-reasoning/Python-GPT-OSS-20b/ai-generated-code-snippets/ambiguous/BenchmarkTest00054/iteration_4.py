import logging
from flask import make_response, request, render_template, abort, jsonify
import urllib.parse
import hashlib
import base64
from pathlib import Path
from helpers.utils import escape_for_html, TESTFILES_DIR

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init(app):
    domain = str(app.config.get('COOKIE_DOMAIN', 'localhost'))

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def benchmark_test_00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        secure = request.is_secure
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=180,
            secure=secure,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain=domain
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def benchmark_test_00054_post():
        cookie_value = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00054', ''))
        data = f'{cookie_value}SomeOKString'
        if not data:
            abort(400, 'Cannot generate hash: Input was empty.')
        hash_bytes = hashlib.sha256(data.encode('utf-8')).digest()
        file_dir = Path(TESTFILES_DIR)
        file_dir.mkdir(parents=True, exist_ok=True)
        file_path = file_dir / 'passwordFile.txt'
        try:
            with file_path.open('a', encoding='utf-8') as f:
                f.write(f'hash_value={base64.b64encode(hash_bytes).decode()}\n')
        except OSError as e:
            logger.exception("Error writing hash to file.")
            abort(500, 'Error writing hash to file.')
        return jsonify(message=f"Sensitive value '{escape_for_html(data)}' hashed and stored.")

    @app.route('/benchmark/hash-00/BenchmarkTest00054/delete', methods=['POST'])
    def benchmark_test_00054_delete():
        response = make_response(jsonify(message='Cookie deleted.'))
        response.set_cookie(
            'BenchmarkTest00054',
            '',
            expires=0,
            path=request.path,
            domain=domain
        )
        return response