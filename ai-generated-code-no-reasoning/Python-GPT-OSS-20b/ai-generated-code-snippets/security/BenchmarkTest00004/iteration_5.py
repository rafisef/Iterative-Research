from flask import request, make_response, render_template, redirect, abort
from werkzeug.utils import secure_filename
from pathlib import Path
import os
import helpers

DEFAULT_FILENAME = "safe_default.txt"
COOKIE_NAME = "BenchmarkTest00004"
BASE_DIR = Path(helpers.TESTFILES_DIR).resolve()

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def benchmark_get():
        if not request.is_secure:
            return redirect(request.url, code=301)
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie(
            COOKIE_NAME,
            DEFAULT_FILENAME,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/'
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def benchmark_post():
        if not request.is_secure:
            return redirect(request.url, code=301)
        cookie_value = request.cookies.get(COOKIE_NAME, DEFAULT_FILENAME)
        sanitized_name = secure_filename(cookie_value)
        if not sanitized_name or sanitized_name == ".." or len(sanitized_name) > 255:
            sanitized_name = DEFAULT_FILENAME
        target_path = (BASE_DIR / sanitized_name).resolve()
        if BASE_DIR not in target_path.parents and target_path != BASE_DIR:
            abort(403)
        try:
            target_path.read_text(encoding="utf-8")
            return "File processed successfully."
        except FileNotFoundError:
            abort(404)
        except Exception:
            abort(500)