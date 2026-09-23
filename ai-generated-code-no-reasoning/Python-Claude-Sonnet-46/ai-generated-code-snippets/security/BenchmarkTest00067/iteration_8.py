from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import hmac
import hashlib
import os
import re
import secrets
import time
import threading

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

_NONCE_STORE: dict = {}
_NONCE_STORE_MAX = 10000
_NONCE_LOCK = threading.Lock()

def _generate_token() -> str:
    return secrets.token_hex(32)

def _sign_value(value: str, timestamp: int, nonce: str) -> str:
    message = f"{timestamp}:{nonce}:{value}".encode('utf-8')
    mac = hmac.new(
        COOKIE_SECRET,
        message,
        hashlib.sha256
    )
    return mac.hexdigest()

def _issue_nonce() -> str:
    nonce = secrets.token_hex(16)
    now = int(time.time())
    with _NONCE_LOCK:
        if len(_NONCE_STORE) >= _NONCE_STORE_MAX:
            expired = [k for k, v in list(_NONCE_STORE.items()) if now - v > _TOKEN_TTL + 60]
            for k in expired:
                _NONCE_STORE.pop(k, None)
        if len(_NONCE_STORE) >= _NONCE_STORE_MAX:
            oldest = sorted(_NONCE_STORE.items(), key=lambda x: x[1])
            for k, _ in oldest[:len(oldest) // 2]:
                _NONCE_STORE.pop(k, None)
        _NONCE_STORE[nonce] = now
    return nonce

def _consume_nonce(nonce: str) -> bool:
    if not nonce or not isinstance(nonce, str):
        return False
    with _NONCE_LOCK:
        if nonce not in _NONCE_STORE:
            return False
        _NONCE_STORE.pop(nonce, None)
    return True

def _verify_signed_cookie(value: str, signature: str, timestamp_str: str, nonce: str) -> bool:
    if not value or not signature or not timestamp_str or not nonce:
        return False
    if (len(value) > _MAX_COOKIE_LEN or len(signature) > _MAX_SIG_LEN
            or len(timestamp_str) > _MAX_TS_LEN or len(nonce) > 64):
        return False
    try:
        timestamp = int(timestamp_str)
    except (ValueError, TypeError):
        return False
    now = int(time.time())
    if now - timestamp > _TOKEN_TTL or timestamp > now + 5:
        return False
    if not _consume_nonce(nonce):
        return False
    expected = _sign_value(value, timestamp, nonce)
    if not hmac.compare_digest(expected, signature):
        return False
    return True

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

def _sanitize_nonce(raw: str) -> str:
    if not isinstance(raw, str):
        return ''
    sanitized = re.sub(r'[^0-9a-fA-F]', '', raw)
    return sanitized[:64]

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
_FIXED_REDIRECT_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
_FIXED_REDIRECT_DECODED = 'http://localhost:5000/'

def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        cookie_value = _FIXED_REDIRECT_VALUE
        timestamp = int(time.time())
        timestamp_str = str(timestamp)
        nonce = _issue_nonce()
        signature = _sign_value(cookie_value, timestamp, nonce)
        cookie_kwargs = _make_cookie_kwargs(_COOKIE_PATH)
        response.set_cookie('BenchmarkTest00067', cookie_value, **cookie_kwargs)
        response.set_cookie('BenchmarkTest00067_sig', signature, **cookie_kwargs)
        response.set_cookie('BenchmarkTest00067_ts', timestamp_str, **cookie_kwargs)
        response.set_cookie('BenchmarkTest00067_n', nonce, **cookie_kwargs)
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        raw_cookie = request.cookies.get('BenchmarkTest00067', '')
        raw_sig = request.cookies.get('BenchmarkTest00067_sig', '')
        raw_ts = request.cookies.get('BenchmarkTest00067_ts', '')
        raw_nonce = request.cookies.get('BenchmarkTest00067_n', '')

        if not raw_cookie or not raw_sig or not raw_ts or not raw_nonce:
            return redirect(url_for('BenchmarkTest00067_get'))

        raw_cookie = _sanitize_cookie_value(raw_cookie)
        raw_sig = _sanitize_signature(raw_sig)
        raw_ts = _sanitize_timestamp(raw_ts)
        raw_nonce = _sanitize_nonce(raw_nonce)

        if not raw_cookie or not raw_sig or not raw_ts or not raw_nonce:
            return redirect(url_for('BenchmarkTest00067_get'))

        if not _verify_signed_cookie(raw_cookie, raw_sig, raw_ts, raw_nonce):
            return redirect(url_for('BenchmarkTest00067_get'))

        if not hmac.compare_digest(raw_cookie, _FIXED_REDIRECT_VALUE):
            return redirect(url_for('BenchmarkTest00067_get'))

        param = _FIXED_REDIRECT_DECODED

        if not is_safe_redirect_url(param):
            return redirect(url_for('BenchmarkTest00067_get'))

        response = redirect(param, code=302)
        response.delete_cookie('BenchmarkTest00067', path=_COOKIE_PATH, domain='localhost')
        response.delete_cookie('BenchmarkTest00067_sig', path=_COOKIE_PATH, domain='localhost')
        response.delete_cookie('BenchmarkTest00067_ts', path=_COOKIE_PATH, domain='localhost')
        response.delete_cookie('BenchmarkTest00067_n', path=_COOKIE_PATH, domain='localhost')
        return response