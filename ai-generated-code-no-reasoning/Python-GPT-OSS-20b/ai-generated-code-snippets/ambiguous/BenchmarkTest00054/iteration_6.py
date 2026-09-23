import logging
import urllib.parse
import hashlib
import base64
from pathlib import Path
from flask import make_response, request, render_template, abort, jsonify
from helpers.utils import escape_for_html, TESTFILES_DIR

logger = logging.getLogger(__name__)

COOKIE_NAME = "BenchmarkTest00054"
FILE_PATH = Path(TESTFILES_DIR) / "passwordFile.txt"

def init(app):
    domain = str(app.config.get("COOKIE_DOMAIN", "localhost"))

    def set_cookie(resp, value, max_age=None, expires=None):
        resp.set_cookie(
            COOKIE_NAME,
            value,
            max_age=max_age,
            expires=expires,
            path=request.path,
            domain=domain,
            secure=request.is_secure,
            httponly=True,
            samesite="Strict",
        )

    def write_hash_to_file(hash_bytes):
        try:
            FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with FILE_PATH.open("a", encoding="utf-8") as f:
                f.write(f"hash_value={base64.b64encode(hash_bytes).decode()}\n")
        except OSError:
            logger.exception("Error writing hash to file.")
            abort(500, "Error writing hash to file.")

    @app.route("/benchmark/hash-00/BenchmarkTest00054", methods=["GET", "POST"])
    def benchmark_test_00054():
        if request.method == "GET":
            resp = make_response(render_template("web/hash-00/BenchmarkTest00054.html"))
            set_cookie(resp, "someSecret", max_age=180)
            return resp

        cookie_value = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, ""))
        data = f"{cookie_value}SomeOKString"
        hash_bytes = hashlib.sha256(data.encode("utf-8")).digest()
        write_hash_to_file(hash_bytes)
        return jsonify(
            message=f"Sensitive value '{escape_for_html(data)}' hashed and stored."
        )

    @app.route("/benchmark/hash-00/BenchmarkTest00054/delete", methods=["POST"])
    def benchmark_test_00054_delete():
        resp = make_response(jsonify(message="Cookie deleted."))
        set_cookie(resp, "", expires=0)
        return resp