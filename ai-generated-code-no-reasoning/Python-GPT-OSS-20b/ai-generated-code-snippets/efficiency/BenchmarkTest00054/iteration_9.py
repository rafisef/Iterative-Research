from flask import request, make_response, render_template
import hashlib, base64, os
import helpers.utils

_FILE_PATH = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
_COOKIE_NAME = 'BenchmarkTest00054'
_TEMPLATE_PATH = 'web/hash-00/BenchmarkTest00054.html'

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET', 'POST'])
    def benchmark_test_00054():
        if request.method == 'GET':
            resp = make_response(render_template(_TEMPLATE_PATH))
            resp.set_cookie(_COOKIE_NAME, 'someSecret',
                            max_age=180, secure=True,
                            path='/benchmark/hash-00/BenchmarkTest00054',
                            domain='localhost')
            return resp
        cookie_value = request.cookies.get(_COOKIE_NAME, 'noCookieValueSupplied')
        bar = cookie_value + 'SomeOKString'
        digest = hashlib.md5(bar.encode()).digest()
        with open(_FILE_PATH, 'ab') as f:
            f.write(b'hash_value=' + base64.b64encode(digest) + b'\n')
        safe_input = helpers.utils.escape_for_html(bar)
        return f"Sensitive value '{safe_input}' hashed and stored."