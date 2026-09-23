from pathlib import Path
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
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def post_benchmark_test_00004():
        cookie_value = request.cookies.get('BenchmarkTest00004', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)

        condition = 7 * 18 + 106 > 200
        bar = 'This_should_always_happen' if condition else param

        file_path = Path(TESTFILES_DIR) / bar
        parts = []

        try:
            with file_path.open('r', encoding='utf-8') as f:
                parts.append(f"Access to file: '{escape_for_html(f.name)}' created.")
                parts.append(" And file already exists.")
        except FileNotFoundError:
            parts.append(" But file doesn't exist yet.")

        return ''.join(parts)