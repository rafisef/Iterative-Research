from flask import request, make_response, render_template
import urllib.parse
import hashlib
import base64
import helpers.utils
import os

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
        bar = urllib.parse.unquote_plus(cookie_value) + 'SomeOKString'
        if not bar:
            return 'Cannot generate hash: Input was empty.'
        digest = hashlib.md5(bar.encode()).digest()
        file_path = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
        with open(file_path, 'a') as f:
            f.write(f'hash_value={base64.b64encode(digest).decode()}\n')
        safe_input = helpers.utils.escape_for_html(bar)
        return f"Sensitive value '{safe_input}' hashed and stored."