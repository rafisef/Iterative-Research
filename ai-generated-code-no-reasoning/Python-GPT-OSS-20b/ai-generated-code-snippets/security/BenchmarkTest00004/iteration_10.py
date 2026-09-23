import pathlib
from flask import abort, current_app, g, request, make_response
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import helpers

BASE_DIR = pathlib.Path(helpers.TESTFILES_DIR).resolve()
DEFAULT_FILENAME = "safe_default.txt"

if not BASE_DIR.is_absolute():
    raise RuntimeError("BASE_DIR must be an absolute path")
if not BASE_DIR.is_dir():
    raise RuntimeError("BASE_DIR does not exist or is not a directory")
if not os.access(BASE_DIR, os.R_OK):
    raise RuntimeError("BASE_DIR is not readable")

def init(app):
    app.before_request(before_request)

def before_request():
    if request.method == "GET":
        cookie_value = request.cookies.get("benchmark_cookie")
        if not cookie_value:
            cookie_value = URLSafeTimedSerializer(current_app.secret_key).dumps(DEFAULT_FILENAME)
        else:
            serializer = URLSafeTimedSerializer(current_app.secret_key)
            try:
                cookie_value = serializer.loads(cookie_value, max_age=180, salt="benchmark_cookie")
            except (BadSignature, SignatureExpired):
                cookie_value = DEFAULT_FILENAME
        response = make_response()
        response.set_cookie(
            "benchmark_cookie",
            cookie_value,
            max_age=180,
            secure=True,
            httponly=True,
            samesite="Strict",
            path="/",
        )
        g.response = response
    if request.method == "POST":
        if not request.is_secure:
            abort(403)
        cookie_value = request.cookies.get("benchmark_cookie")
        if not cookie_value:
            abort(403)
        serializer = URLSafeTimedSerializer(current_app.secret_key)
        try:
            filename = serializer.loads(cookie_value, max_age=180, salt="benchmark_cookie")
        except (BadSignature, SignatureExpired):
            abort(403)
        sanitized_name = secure_filename(filename)
        if not sanitized_name or sanitized_name == ".." or len(sanitized_name) > 255:
            sanitized_name = DEFAULT_FILENAME
        try:
            target_path = (BASE_DIR / sanitized_name).resolve(strict=True)
        except Exception:
            abort(403)
        if target_path.parent != BASE_DIR or not target_path.is_file():
            abort(404)
        try:
            target_path.read_text(encoding="utf-8")
        except Exception:
            abort(500)