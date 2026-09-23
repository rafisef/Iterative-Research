from flask import request, make_response, render_template
import hashlib
import base64
import helpers.utils
import os

_cache = {}

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET', 'POST'])
    def benchmark_test_00054():
        if request.method == 'GET':
            resp = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
            resp.set_cookie('BenchmarkTest00054', 'someSecret',
                            max_age=180, secure=True,
                            path='/benchmark/hash-00/BenchmarkTest00054',
                            domain='localhost')
            return resp
        cookie_value = request.cookies.get('BenchmarkTest00054', 'noCookieValueSupplied')
        bar = cookie_value + 'SomeOKString'
        if not bar:
            return 'Cannot generate hash: Input was empty.'
        digest = _cache.get(bar)
        if digest is None:
            digest = hashlib.md5(bar.encode()).digest()
            _cache[bar] = digest
        file_path = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
        with open(file_path, 'ab') as f:
            f.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
        safe_input = helpers.utils.escape_for_html(bar)
        return f"Sensitive value '{safe_input}' hashed and stored."