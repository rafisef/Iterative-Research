from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import hashlib
import base64
import helpers.utils

def init(app):
    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie(
            'BenchmarkTest00054',
            'someSecret',
            max_age=60 * 3,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        cookie_value = request.cookies.get('BenchmarkTest00054', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)
        bar = param + 'SomeOKString'

        if not bar:
            return 'Cannot generate hash: Input was empty.'

        hash_obj = hashlib.md5()
        hash_obj.update(bar.encode('utf-8'))
        digest = hash_obj.digest()

        file_path = f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'
        with open(file_path, 'a') as f:
            f.write(f'hash_value={base64.b64encode(digest)}\n')

        safe_input = helpers.utils.escape_for_html(bar)
        return f"Sensitive value '{safe_input}' hashed and stored."