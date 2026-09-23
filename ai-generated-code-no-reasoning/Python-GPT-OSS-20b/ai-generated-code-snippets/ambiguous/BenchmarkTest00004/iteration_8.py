from pathlib import Path
import urllib.parse
from flask import make_response, request, render_template, abort
from helpers.utils import escape_for_html, TESTFILES_DIR

BASE_DIR = Path(TESTFILES_DIR).resolve()

def safe_path(name: str) -> Path:
    path = (BASE_DIR / Path(name).name).resolve()
    if not str(path).startswith(str(BASE_DIR)):
        abort(400)
    return path

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=('GET', 'POST'))
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
        cookie = request.cookies.get('BenchmarkTest00004', '')
        name = urllib.parse.unquote_plus(cookie) or 'This_should_always_happen'
        path = safe_path(name)
        if path.is_file():
            return f"Access to file: '{escape_for_html(path)}' created. And file already exists."
        return " But file doesn't exist yet."