from flask import Blueprint, request, make_response, render_template
import base64
import pickle
from helpers import utils

bp = Blueprint('benchmark', __name__)

COOKIE_NAME = 'BenchmarkTest00078'
COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b_towaGNlbGUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
COOKIE_MAX_AGE = 180
PAYLOAD_START = 4
PAYLOAD_END = -17

def _extract_payload(cookie_value: str) -> str | None:
    if not cookie_value:
        return None
    return cookie_value[PAYLOAD_START:PAYLOAD_END]

def _deserialize(payload: str) -> bool:
    try:
        data = base64.urlsafe_b64decode(payload)
        pickle.loads(data)
        return True
    except Exception:
        return False

@bp.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET', 'POST'])
def benchmark_test_00078() -> str:
    if request.method == 'GET':
        resp = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        resp.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            path=request.path,
        )
        return resp
    payload = _extract_payload(request.cookies.get(COOKIE_NAME))
    if payload is None or not _deserialize(payload):
        return 'Unpickling failed!', 400
    utils.sharedstr = 'no pickles to be seen here'
    return f'shared string is {utils.sharedstr}'

def init(app) -> None:
    app.register_blueprint(bp)