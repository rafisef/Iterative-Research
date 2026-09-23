import os
import pathlib
from pathlib import Path
from flask import abort, current_app, g, request, make_response
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import helpers

BASE_DIR = Path(helpers.TESTFILES_DIR).resolve()

DEFAULT_FILENAME = "safe_default.txt"
if not os.path.isabs(BASE_DIR):
    raise RuntimeError("BASE_DIR must be an absolute path")
if not os.path.isdir(BASE_DIR):
    raise RuntimeError("BASE_DIR does not exist or is not a directory")
if not os.access(BASE_DIR, os.R_OK):
    raise RuntimeError("BASE_DIR is not readable")

def init(app: "flask.Flask") -> None:
    app.before_request(before_request)

def before_request() -> None:
    if request.method == "GET":
        cookie_value = request.cookies.get("benchmark_cookie")
        if not cookie_value:
            cookie_value = (
                URLSafeTimedSerializer(current_app.secret_key)
                .dumps(DEFAULT_FILENAME)
                .decode()
            )
        else:
            serializer = URLSafeTimedSerializer(current_app.secret_key)
            try:
                cookie_value = serializer.loads(
                    cookie_value, max_age=180, salt="benchmark_cookie"
                )
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
        if request.is_secure:
            cookie_value = request.cookies.get("benchmark_cookie")
            if not cookie_value:
                abort(403)
            try:
                serializer = URLSafeTimedSerializer(current_app.secret_key)
                filename = serializer.loads(
                    cookie_value, max_age=180, salt="benchmark_cookie"
                )
            except (BadSignature, SignatureExpired):
                abort(403)
            sanitized_name = secure_filename(filename)
            if not sanitized_name or sanitized_name == ".." or len(sanitized_name) > 255:
                sanitized_name = DEFAULT_FILENAME
            target_path = BASE_DIR / sanitized_name
            try:
                target_path = target_path.resolve()
            except Exception:
                abort(403)
            try:
                target_path.relative_to(BASE_DIR)
            except ValueError:
                abort(403)
            if not target_path.is_file():
                abort(404)
            try:
                _ = target_path.read_text()
            except Exception:
                abort(500)
        else:
            abort(403)