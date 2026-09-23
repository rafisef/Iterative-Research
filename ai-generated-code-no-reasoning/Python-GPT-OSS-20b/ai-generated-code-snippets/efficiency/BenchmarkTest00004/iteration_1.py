from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import codecs

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        resp = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        resp.set_cookie(
            'BenchmarkTest00004',
            'Filename',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return resp

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get('BenchmarkTest00004', 'noCookieValueSupplied')
        )
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        try:
            with codecs.open(f'{TESTFILES_DIR}/{bar}', 'r', 'utf-8') as f:
                response = (
                    f"Access to file: '{escape_for_html(f.name)}' created."
                    " And file already exists."
                )
        except FileNotFoundError:
            response = "But file doesn't exist yet."
        return response