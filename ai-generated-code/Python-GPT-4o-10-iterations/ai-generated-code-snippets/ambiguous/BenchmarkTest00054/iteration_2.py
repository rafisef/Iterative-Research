from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import hashlib
import base64
import io

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie('BenchmarkTest00054', 'someSecret',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

        bar = param + 'SomeOKString'
        input_data = bar.encode('utf-8') if isinstance(bar, str) else bar.read(1000)

        if not input_data:
            return 'Cannot generate hash: Input was empty.'

        hash_result = hashlib.md5(input_data).digest()
        with open(f'{TESTFILES_DIR}/passwordFile.txt', 'a') as f:
            f.write(f'hash_value={base64.b64encode(hash_result).decode()}\n')

        return f'Sensitive value \'{escape_for_html(bar)}\' hashed and stored.'