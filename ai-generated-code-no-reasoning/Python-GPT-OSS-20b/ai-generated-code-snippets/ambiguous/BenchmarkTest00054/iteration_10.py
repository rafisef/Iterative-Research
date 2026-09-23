import logging
import hashlib
import base64
import datetime
import os
import tempfile
from pathlib import Path
from typing import List, Optional

from flask import (
    Flask,
    Blueprint,
    request,
    make_response,
    render_template,
    abort,
    jsonify,
    Response,
)

from helpers.utils import escape_for_html, TESTFILES_DIR

logger = logging.getLogger(__name__)

COOKIE_NAME = os.getenv("COOKIE_NAME", "BenchmarkTest00054")
COOKIE_PATH = os.getenv("COOKIE_PATH", "/benchmark/hash-00/BenchmarkTest00054")
COOKIE_MAX_AGE = int(os.getenv("COOKIE_MAX_AGE", "180"))
FILE_PATH = Path(os.getenv("HASH_FILE_PATH", TESTFILES_DIR)) / "passwordFile.txt"

bp = Blueprint("benchmark_test_00054", __name__, url_prefix=COOKIE_PATH)


def set_cookie(resp: Response, value: str, max_age: Optional[int] = None, expires: Optional[datetime.datetime] = None) -> None:
    domain = request.host.split(":")[0]
    resp.set_cookie(
        COOKIE_NAME,
        value,
        max_age=max_age,
        expires=expires,
        path=COOKIE_PATH,
        domain=domain,
        secure=request.is_secure,
        httponly=True,
        samesite="Strict",
    )


def write_hash_to_file(hash_bytes: bytes) -> None:
    try:
        FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile("w", delete=False, dir=FILE_PATH.parent, encoding="utf-8")
        with tmp as f:
            f.write(
                f"hash_value={base64.b64encode(hash_bytes).decode()} "
                f"timestamp={datetime.datetime.utcnow().isoformat()}\n"
            )
        os.replace(tmp.name, FILE_PATH)
    except OSError:
        logger.exception("Error writing hash to file.")
        abort(500, "Error writing hash to file.")


def read_hash_file() -> List[str]:
    try:
        return FILE_PATH.read_text(encoding="utf-8").strip().splitlines()
    except FileNotFoundError:
        return []
    except OSError:
        logger.exception("Error reading hash file.")
        abort(500, "Error reading hash file.")


def delete_hash_file() -> None:
    try:
        FILE_PATH.unlink(missing_ok=True)
    except OSError:
        logger.exception("Error deleting hash file.")
        abort(500, "Error deleting hash file.")


@bp.route("/", methods=["GET", "POST"])
def benchmark_test_00054() -> Response:
    if request.method == "GET":
        resp = make_response(render_template("web/hash-00/BenchmarkTest00054.html"))
        set_cookie(resp, "someSecret", max_age=COOKIE_MAX_AGE)
        return resp
    cookie_value = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, ""))
    data = f"{cookie_value}SomeOKString"
    hash_bytes = hashlib.sha256(data.encode("utf-8")).digest()
    write_hash_to_file(hash_bytes)
    return jsonify(message=f"Sensitive value '{escape_for_html(data)}' hashed and stored.")


@bp.route("/delete", methods=["POST"])
def benchmark_test_00054_delete() -> Response:
    resp = make_response(jsonify(message="Cookie deleted."))
    set_cookie(resp, "", expires=0)
    return resp


@bp.route("/hashes", methods=["GET"])
def benchmark_test_00054_hashes() -> Response:
    hashes = read_hash_file()
    return jsonify(hashes=hashes)


@bp.route("/purge", methods=["POST"])
def benchmark_test_00054_purge() -> Response:
    delete_hash_file()
    return jsonify(message="All hashes purged.")


def init(app: Flask) -> None:
    app.register_blueprint(bp)