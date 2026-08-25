from flask import Flask, redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import asyncio

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
    async def BenchmarkTest00054_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

        string26833 = ''
        data12 = ''
        copy = string26833
        string26833 = ''
        string26833 += param
        copy += 'SomeOKString'
        bar = copy

        import hashlib, base64
        import io, helpers.utils

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

        hash = hashlib.new('md5')
        hash.update(input)

        result = hash.digest()
        await asyncio.to_thread(write_to_file, base64.b64encode(result), input)

        RESPONSE += (
            f'Sensitive value \'{helpers.utils.escape_for_html(input.decode("utf-8"))}\' hashed and stored.'
        )

        return RESPONSE

def write_to_file(encoded_result, input):
    with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
        f.write(f'hash_value={encoded_result}\n')