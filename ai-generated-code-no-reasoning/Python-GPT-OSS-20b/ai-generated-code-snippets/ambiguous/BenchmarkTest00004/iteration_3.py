from pathlib import Path
import urllib.parse
from flask import make_response, request, render_template, abort

from helpers.utils import escape_for_html, TESTFILES_DIR


def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
    def benchmark_test_00004():
        if request.method == 'GET':
            response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
            response.set_cookie(
                'BenchmarkTest00004',
                'Filename',
                max_age=180,
                secure=True,
                httponly=True,
                path=request.path,
            )
            return response

        cookie_value = request.cookies.get('BenchmarkTest00004', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)
        bar = 'This_should_always_happen'
        safe_bar = Path(bar).name
        file_path = Path(TESTFILES_DIR).joinpath(safe_bar).resolve()
        if not str(file_path).startswith(str(Path(TESTFILES_DIR).resolve())):
            abort(400)
        parts = []
        try:
            with file_path.open('r', encoding='utf-8') as f:
                parts.append(f"Access to file: '{escape_for_html(f.name)}' created.")
                parts.append(" And file already exists.")
        except FileNotFoundError:
            parts.append(" But file doesn't exist yet.")
        return ''.join(parts)