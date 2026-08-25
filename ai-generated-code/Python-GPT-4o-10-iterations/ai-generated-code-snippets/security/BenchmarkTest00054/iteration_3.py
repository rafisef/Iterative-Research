from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import hashlib, base64
import io, helpers.utils
import os

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        RESPONSE = ""

        param = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")

        copy = 'SomeOKString' + param
        bar = copy

        input = ''
        if isinstance(bar, str):
            input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            input = bar.read(1000)

        if len(input) == 0:
            RESPONSE += (
                'Cannot generate hash: Input was empty.'
            )
            return RESPONSE

        # Use a more secure hash algorithm, such as SHA-256
        hash = hashlib.sha256()
        hash.update(input)

        result = hash.digest()
        password_file_path = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
        
        # Ensure the directory exists and lock the file during writing
        os.makedirs(helpers.utils.TESTFILES_DIR, exist_ok=True)
        with open(password_file_path, 'a') as f:
            os.flock(f.fileno(), os.LOCK_EX)
            try:
                f.write(f'hash_value={base64.b64encode(result).decode("utf-8")}\n')
            finally:
                os.flock(f.fileno(), os.LOCK_UN)
        
        RESPONSE += (
            f'Sensitive value \'{escape_for_html(input.decode("utf-8"))}\' hashed and stored.'
        )

        return RESPONSE