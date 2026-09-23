from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import re
import urllib.parse
import configparser
import secrets
import hmac
import hashlib
import os

ALLOWED_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.\ ]+$')
MAX_PARAM_LENGTH = 256
COOKIE_NAME = 'BenchmarkTest00074'

HMAC_SECRET = os.environ.get('COOKIE_HMAC_SECRET')
if not HMAC_SECRET or len(HMAC_SECRET) < 64:
    raise RuntimeError("COOKIE_HMAC_SECRET environment variable must be set and at least 64 characters.")

HMAC_SECRET_BYTES = HMAC_SECRET.encode('utf-8')

def sign_cookie_value(value: str) -> str:
    sig = hmac.new(HMAC_SECRET_BYTES, value.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{value}|{sig}"

def verify_cookie_value(signed_value: str):
    if '|' not in signed_value:
        return None
    value, _, sig = signed_value.rpartition('|')
    expected_sig = hmac.new(HMAC_SECRET_BYTES, value.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.encode('utf-8'), expected_sig.encode('utf-8')):
        return None
    return value

STATIC_COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
SIGNED_STATIC_VALUE = sign_cookie_value(STATIC_COOKIE_VALUE)

def _sanitize_and_validate(raw_signed: str):
    if not raw_signed:
        return None, ("Missing cookie.", 400)

    if len(raw_signed) > MAX_PARAM_LENGTH * 2 + 65:
        return None, ("Cookie value exceeds maximum allowed length.", 400)

    verified_raw = verify_cookie_value(raw_signed)
    if verified_raw is None:
        return None, ("Cookie integrity check failed.", 400)

    try:
        param = urllib.parse.unquote_plus(verified_raw)
    except Exception:
        return None, ("Failed to decode cookie value.", 400)

    if len(param) > MAX_PARAM_LENGTH:
        return None, ("Input exceeds maximum allowed length.", 400)

    if not ALLOWED_PATTERN.match(param):
        return None, ("Invalid input detected.", 400)

    return param[:MAX_PARAM_LENGTH], None

def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            COOKIE_NAME,
            SIGNED_STATIC_VALUE,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        raw_signed = request.cookies.get(COOKIE_NAME, "")

        safe_param, error = _sanitize_and_validate(raw_signed)
        if error is not None:
            return escape_for_html(error[0]), error[1]

        conf90091 = configparser.RawConfigParser()
        conf90091.read_dict({
            'section90091': {
                'keyA-90091': 'a-Value',
                'keyB-90091': safe_param
            }
        })

        try:
            bar = conf90091.get('section90091', 'keyB-90091')
        except configparser.Error:
            return escape_for_html("Failed to retrieve configuration value."), 500

        if len(bar) > MAX_PARAM_LENGTH:
            return escape_for_html("Retrieved value exceeds maximum allowed length."), 400

        if not ALLOWED_PATTERN.match(bar):
            return escape_for_html("Invalid value retrieved from config."), 400

        return escape_for_html(bar)