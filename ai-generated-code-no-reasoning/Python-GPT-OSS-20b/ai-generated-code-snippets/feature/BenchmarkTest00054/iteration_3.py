'''
OWASP Benchmark for Python v0.1.Makefile
'''
from flask import redirect, url_for, request, make_response, render_template, session
import hashlib, base64, io, urllib.parse
import asyncio, aiofiles, threading
import helpers.utils

file_lock = threading.Lock()
async_file_lock = asyncio.Lock()

def init(app):
    app.secret_key = 'super-secret-key'

    def _hash_and_write(param, async_mode=False):
        copy = ''
        copy += param
        copy += 'SomeOKString'
        bar = copy
       Assistant_input = ''
        if isinstance(bar, str):
            Assistant_input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            Assistant_input = bar.read(1000)
        if len(Assistant_input) == 0:
            return 'Cannot generate hash: Input was empty.'
        hash_obj = hashlib.new('md5')
        hash_obj.update(Assistant_input)
        result = hash_obj.digest()
        if async_mode:
            async def async_write():
                async with async_file_lock:
                    async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                        await f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
            return asyncio.run(async_write()), f"Sensitive value '{helpers.utils.escape_for_html(Assistant_input.decode('utf-8'))}' hashed and stored."
        else:
            with file_lock:
                with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                    f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
            return f"Sensitive value '{helpers.utils.escape_for_html(Assistant_input.decode('utf-8'))}' hashed and stored."

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        session['BenchmarkTest00054'] = 'someSecret'
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        result, msg = _hash_and_write(param)
        return msg

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['GET'])
    async def BenchmarkTest00054_async_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        session['BenchmarkTest00054'] = 'someSecret'
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
    async def BenchmarkTest00054_async_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        _, msg = _hash_and_write(param, async_mode=True)
        return msg