from pathlib import Path
import codecs
import urllib.parse

from flask import make_response, request, render_template

from helpers.utils import escape_for_html, TESTFILES_DIR


def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def get_benchmark_test_00004():
        response = make_response(
            render_template('web/pathtraver-00/BenchmarkTest00004.html')
        )
        response.set_cookie(
            'BenchmarkTest00004',
            'Filename',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost',
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def post_benchmark_test_00004():
        cookie_value = request.cookies.get('BenchmarkTest00004', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)

        num = 106
        condition = 7 * 18 + num > 200
        bar = 'This_should_always_happen' if condition else param

        file_path = Path(TESTFILES_DIR) / bar
        response = ""

        try:
            with codecs.open(file_path, 'r', 'utf-8') as file_target:
                response += f"Access to file: '{escape_for_html(file_target.name)}' created."
                response += " And file already exists."
        except FileNotFoundError:
            response += " But file doesn't exist yet."

        return response