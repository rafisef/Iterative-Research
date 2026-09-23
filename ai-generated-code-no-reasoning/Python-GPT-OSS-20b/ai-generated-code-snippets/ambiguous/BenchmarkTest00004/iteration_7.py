from pathlib import Path
import urllib.parse
from flask import make_response, request, render_template, abort

from helpers.utils import escape_for_html, TESTFILES_DIR

BASE_DIR = Path(TESTFILES_DIR).resolve()

def _safe_path(name: str) -> Path:
    safe_name = Path(name).name
    full_path = (BASE_DIR / safe_name).resolve()
    if not str(full_path).startswith(str(BASE_DIR)):
        abort(400)
    return full_path

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
    def benchmark_test_00004():
        if request.method == 'GET':
            resp = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
            resp.set_cookie(
                'BenchmarkTest00004',
                'Filename',
                max_age=180,
                secure=request.is_secure,
                httponly=True,
                path=request.path,
            )
            return resp

        cookie_value = request.cookies.get('BenchmarkTest00004', '')
        param = urllib.parse.unquote_plus(cookie_value)
        file_name = param or 'This_should_always_happen'
        file_path = _safe_path(file_name)

        try:
            with file_path.open('r', encoding='utf-8') as f:
                return (
                    f"Access to file: '{escape_for_html(f.name)}' created."
                    " And file already exists."
                )
        except FileNotFoundError:
            return " But file doesn't exist yet."