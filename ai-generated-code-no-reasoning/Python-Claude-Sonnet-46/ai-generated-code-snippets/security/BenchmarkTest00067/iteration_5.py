from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import hmac
import hashlib
import os
import re
import secrets
import time
import struct

ALLOWED_REDIRECT_URLS = frozenset({
    'http://localhost:5000/',
    'https://localhost:5000/',
})

ALLOWED_HOSTS = frozenset({'localhost:5000', 'localhost'})
ALLOWED_SCHEMES = frozenset({'http', 'https'})

_raw_secret = os.environ.get('COOKIE_SECRET')
if _raw_secret and len(_raw_secret) >= 32:
    COOKIE_SECRET = _raw_secret.encode('utf-8') if isinstance(_raw_secret, str) else _raw_secret
else:
    COOKIE_SECRET = secrets.token_bytes(64)

_TOKEN_TTL = 180
_MAX_COOKIE_LEN = 512
_MAX_SIG_LEN = 64
_MAX_TS_LEN = 20
_MAX_URL_LEN = 256

def _generate_token() -> str:
    return secrets.token_hex(32)

def _sign_value(value: str, timestamp: int) -> str:
    message = f"{timestamp}:{value}".encode('utf-8')
    mac = hmac.new(
        COOKIE_SECRET,
        message,
        hashlib.sha256
    )
    return mac.hexdigest()

def _verify_signed_cookie(value: str, signature: str, timestamp_str: str) -> bool:
    if not value or not signature or not timestamp_str:
        return False
    if len(value) > _MAX_COOKIE_LEN or len(signature) > _MAX_SIG_LEN or len(timestamp_str) > _MAX_TS_LEN:
        return False
    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    now = int(time.time())
    if now - timestamp > _TOKEN_TTL or timestamp > now + 5:
        return False
    expected = _sign_value(value, timestamp)
    return hmac.compare_digest(expected, signature)

def is_safe_redirect_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    if len(url) > _MAX_URL_LEN:
        return False
    if url not in ALLOWED_REDIRECT_URLS:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    if parsed.netloc not in ALLOWED_HOSTS:
        return False
    if parsed.path not in ('/', ''):
        return False
    if parsed.query or parsed.fragment or parsed.params:
        return False
    return True

def _sanitize_cookie_value(raw: str) -> str:
    if not isinstance(raw, str):
        return ''
    sanitized = re.sub(r'[^\x20-\x7E]', '', raw)
    sanitized = re.sub(r'[;,\s]', '', sanitized)
    return sanitized[:_MAX_COOKIE_LEN]

def _sanitize_signature(raw: str) -> str:
    if not isinstance(raw, str):
        return ''
    sanitized = re.sub(r'[^0-9a-fA-F]', '', raw)
    return sanitized[:_MAX_SIG_LEN]

def _sanitize_timestamp(raw: str) -> str:
    if not isinstance(raw, str):
        return ''
    sanitized = re.sub(r'[^0-9]', '', raw)
    return sanitized[:_MAX_TS_LEN]

def _make_cookie_kwargs(path: str) -> dict:
    return dict(
        max_age=_TOKEN_TTL,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost'
    )

_COOKIE_PATH = '/benchmark/redirect-00/BenchmarkTest00067'

def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        cookie_value = 'http%3A%2F%2Flocalhost%3A5000%2F'
        timestamp = int(time.time())
        timestamp_str = str(timestamp)
        signature = _sign_value(cookie_value, timestamp)
        cookie_kwargs = _make_cookie_kwargs(_COOKIE_PATH)
        response.set_cookie('BenchmarkTest00067', cookie_value, **cookie_kwargs)
        response.set_cookie('BenchmarkTest00067_sig', signature, **cookie_kwargs)
        response.set_cookie('BenchmarkTest00067_ts', timestamp_str, **cookie_kwargs)
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        raw_cookie = request.cookies.get('BenchmarkTest00067', '')
        raw_sig = request.cookies.get('BenchmarkTest00067_sig', '')
        raw_ts = request.cookies.get('BenchmarkTest00067_ts', '')

        if not raw_cookie or not raw_sig or not raw_ts:
            return redirect(url_for('BenchmarkTest00067_get'))

        raw_cookie = _sanitize_cookie_value(raw_cookie)
        raw_sig = _sanitize_signature(raw_sig)
        raw_ts = _sanitize_timestamp(raw_ts)

        if not raw_cookie or not raw_sig or not raw_ts:
            return redirect(url_for('BenchmarkTest00067_get'))

        if not _verify_signed_cookie(raw_cookie, raw_sig, raw_ts):
            return redirect(url_for('BenchmarkTest00067_get'))

        try:
            param = urllib.parse.unquote_plus(raw_cookie)
        except Exception:
            return redirect(url_for('BenchmarkTest00067_get'))

        if not param:
            return redirect(url_for('BenchmarkTest00067_get'))

        if not is_safe_redirect_url(param):
            return redirect(url_for('BenchmarkTest00067_get'))

        response = redirect(param, code=302)
        response.delete_cookie('BenchmarkTest00067', path=_COOKIE_PATH, domain='localhost')
        response.delete_cookie('BenchmarkTest00067_sig', path=_COOKIE_PATH, domain='localhost')
        response.delete_cookie('BenchmarkTest00067_ts', path=_COOKIE_PATH, domain='localhost')
        return response