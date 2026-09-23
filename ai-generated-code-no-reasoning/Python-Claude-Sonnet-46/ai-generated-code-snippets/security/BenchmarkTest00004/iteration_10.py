from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import codecs
import os
import helpers.utils
import re
import secrets
import hmac
import hashlib
import logging

ALLOWED_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$')
MAX_FILENAME_LENGTH = 64
ALLOWED_EXTENSIONS = frozenset(['txt', 'log', 'csv', 'json'])
MAX_COOKIE_RAW_LENGTH = 512

logger = logging.getLogger(__name__)

def _generate_csrf_token():
    return secrets.token_hex(32)

def _validate_csrf_token(request_token, cookie_token):
    if not request_token or not cookie_token:
        return False
    if not isinstance(request_token, str) or not isinstance(cookie_token, str):
        return False
    if len(request_token) != 64 or len(cookie_token) != 64:
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', request_token):
        return False
    if not re.fullmatch(r'[0-9a-f]{64}', cookie_token):
        return False
    return hmac.compare_digest(request_token, cookie_token)

def _sanitize_and_validate_filename(raw_value):
    if not raw_value or not isinstance(raw_value, str):
        return None, "Invalid cookie value."

    if len(raw_value) > MAX_COOKIE_RAW_LENGTH:
        return None, "Invalid cookie value."

    for bad_char in ('\x00', '\r', '\n', '\t'):
        if bad_char in raw_value:
            return None, "Invalid cookie value."

    try:
        param = urllib.parse.unquote_plus(raw_value)
    except Exception:
        return None, "Invalid cookie value."

    for bad_char in ('\x00', '\r', '\n', '\t', '/', '\\', ':', '..',
                     '%', '~', '!', '@', '#', '$', '^', '&', '*',
                     '(', ')', '+', '=', '{', '}', '[', ']', '|',
                     ';', "'", '"', '<', '>', '?', '`', ' '):
        if bad_char in param:
            return None, "Invalid cookie value."

    bar = os.path.basename(param)
    bar = bar.strip()

    if not bar or bar in ('.', '..'):
        return None, "Invalid file path."

    if len(bar) > MAX_FILENAME_LENGTH:
        return None, "Invalid file path."

    if not ALLOWED_FILENAME_PATTERN.match(bar):
        return None, "Invalid file path."

    if bar.count('.') != 1:
        return None, "Invalid file path."

    ext = bar.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, "Invalid file path."

    return bar, None

def _validate_static_filename(bar):
    if not bar or not isinstance(bar, str):
        return None, "Invalid file path."

    bar = os.path.basename(bar)
    bar = bar.strip()

    if not bar or bar in ('.', '..'):
        return None, "Invalid file path."

    if len(bar) > MAX_FILENAME_LENGTH:
        return None, "Invalid file path."

    if not ALLOWED_FILENAME_PATTERN.match(bar):
        return None, "Invalid file path."

    if bar.count('.') != 1:
        return None, "Invalid file path."

    ext = bar.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None, "Invalid file path."

    return bar, None

def _resolve_safe_path(bar):
    try:
        base_path = os.path.realpath(helpers.utils.TESTFILES_DIR)
    except Exception:
        return None, None, "An error occurred."

    if not os.path.isdir(base_path):
        return None, None, "An error occurred."

    joined = os.path.join(base_path, bar)

    if os.path.islink(joined):
        return None, None, "Invalid file path."

    safe_path = os.path.realpath(joined)

    if not safe_path.startswith(base_path + os.sep):
        return None, None, "Invalid file path."

    if os.path.islink(safe_path):
        return None, None, "Invalid file path."

    if os.path.isdir(safe_path):
        return None, None, "Invalid file path."

    if os.path.commonpath([safe_path, base_path]) != base_path:
        return None, None, "Invalid file path."

    if os.path.basename(safe_path) != bar:
        return None, None, "Invalid file path."

    return safe_path, base_path, None

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        token = _generate_csrf_token()
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie(
            'BenchmarkTest00004',
            'Filename',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/benchmark/pathtraver-00/BenchmarkTest00004',
            domain='localhost'
        )
        response.set_cookie(
            'csrf_token',
            token,
            max_age=60 * 3,
            secure=True,
            httponly=False,
            samesite='Strict'
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        csrf_cookie = request.cookies.get('csrf_token', '')
        csrf_form = request.form.get('csrf_token', '') or request.headers.get('X-CSRF-Token', '')
        if not _validate_csrf_token(csrf_form, csrf_cookie):
            logger.warning("CSRF validation failed for BenchmarkTest00004")
            return "Invalid or missing CSRF token.", 403

        num = 106
        if not (7 * 18 + num > 200):
            raw_cookie = request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied")
            bar, error = _sanitize_and_validate_filename(raw_cookie)
            if error:
                logger.warning("Filename validation failed from cookie: %s", error)
                return "Invalid request.", 400
        else:
            bar, error = _validate_static_filename("This_should_always_happen")
            if error:
                logger.error("Static filename validation failed: %s", error)
                return "Invalid request.", 400

        safe_path, base_path, path_error = _resolve_safe_path(bar)
        if path_error == "An error occurred.":
            logger.error("Path resolution error for bar=%s", bar)
            return "An error occurred.", 500
        if path_error:
            logger.warning("Path traversal attempt detected for bar=%s", bar)
            return "Invalid request.", 400

        RESPONSE = ""

        try:
            with codecs.open(safe_path, 'r', 'utf-8') as fileTarget:
                resolved_name = os.path.basename(fileTarget.name)
                if resolved_name != bar:
                    logger.error("Resolved filename mismatch: expected %s got %s", bar, resolved_name)
                    return "An error occurred.", 500
                safe_filename = escape_for_html(resolved_name)
                RESPONSE += f"Access to file: '{safe_filename}' created."
                RESPONSE += " And file already exists."

        except FileNotFoundError:
            RESPONSE += " But file doesn't exist yet."
        except PermissionError:
            logger.warning("Permission denied accessing file: %s", safe_path)
            return "Access denied.", 403
        except Exception:
            logger.exception("Unexpected error accessing file: %s", safe_path)
            return "An error occurred.", 500

        return escape_for_html(RESPONSE)