from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import os
import hashlib, base64
import io

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost',
            httponly=True,
            samesite='Lax')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        RESPONSE = ""

        param = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")
        param = escape_for_html(param)

        string26833 = ''
        data12 = ''
        copy = string26833
        string26833 = ''
        string26833 += param
        copy += 'SomeOKString'
        bar = copy

        input = ''
        if isinstance(bar, str):
            input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            input = bar.read(1000)

        if len(input) == 0:
            return 'Cannot generate hash: Input was empty.', 400

        hash = hashlib.sha256()
        hash.update(input)

        result = hash.digest()
        testfiles_dir = os.environ.get('TESTFILES_DIR', '/tmp')

        # Ensure directory exists and is writable
        if not os.path.exists(testfiles_dir):
            return 'Server error: Directory does not exist.', 500
        if not os.access(testfiles_dir, os.W_OK):
            return 'Server error: No write permission for directory.', 500
        
        # Safely write the file
        try:
            with open(os.path.join(testfiles_dir, 'passwordFile.txt'), 'a') as f:
                f.write(f'hash_value={base64.b64encode(result).decode()}\n')
        except IOError:
            return 'Server error: File write operation failed.', 500
        
        RESPONSE += (
            f'Sensitive value \'{escape_for_html(input.decode("utf-8"))}\' hashed and stored.'
        )

        return RESPONSE