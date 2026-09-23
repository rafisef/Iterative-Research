from flask import request, make_response, render_template, redirect, abort
from werkzeug.utils import secure_filename
from pathlib import Path
from itsdangerous import distribute, BadSignature
import helpers

DEFAULT_FILENAME = "safe_default.txt"
COOKIE_NAME = "BenchmarkTest00004"
BASE_DIR = Path(helpers.TESTFILES_DIR).resolve()

def init(app):
    serializer = distribute(app.secret_key, salt="benchmark_cookie")

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def benchmark_get():
        if not request.is_secure:
            return redirect(request.url, code=301)
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        signed = serializer.dumps(DEFAULT_FILENAME)
        response.set_cookie(
            COOKIE_NAME,
            signed,
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
        cookie_value = request.cookies.get(COOKIE_NAME, None)
        try:
            if cookie_value is None:
                raise BadSignature("missing cookie")
            value = serializer.loads(cookie_value)
        except BadSignature:
            value = DEFAULT_FILENAME
        sanitized_name = secure_filename(value)
        if not sanitized_name or sanitized_name == ".." or len(sanitized_name) > 255:
            sanitized_name = DEFAULT_FILENAME
        target_path = (BASE_DIR / sanitized_name).resolve()
        if not (BASE_DIR in target_path.parents or target_path == BASE_DIR):
            abort(403)
        if not target_path.is_file():
            abort(404)
        try:
            target_path.read_text(encoding="utf-8")
            return "File processed successfully."
        except Exception:
            abort(500)