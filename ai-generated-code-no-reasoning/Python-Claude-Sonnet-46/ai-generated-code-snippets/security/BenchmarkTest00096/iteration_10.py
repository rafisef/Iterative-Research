'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import request, make_response
from markupsafe import escape
import html
import re
import unicodedata
import secrets
import hashlib
import logging

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 512
MAX_CONTENT_LENGTH = MAX_INPUT_LENGTH * 10
ALLOWED_PATTERN = re.compile(r'^[\w\s\-.,!?@#+\(\)\[\]]{0,512}$')

_DANGEROUS_PATTERNS = [
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'data\s*:', re.IGNORECASE),
    re.compile(r'vbscript\s*:', re.IGNORECASE),
    re.compile(r'on\w+\s*=', re.IGNORECASE),
    re.compile(r'<\s*script', re.IGNORECASE),
    re.compile(r'<\s*iframe', re.IGNORECASE),
    re.compile(r'<\s*object', re.IGNORECASE),
    re.compile(r'<\s*embed', re.IGNORECASE),
    re.compile(r'<\s*link', re.IGNORECASE),
    re.compile(r'<\s*meta', re.IGNORECASE),
    re.compile(r'expression\s*\(', re.IGNORECASE),
    re.compile(r'url\s*\(', re.IGNORECASE),
    re.compile(r'<\s*svg', re.IGNORECASE),
    re.compile(r'<\s*math', re.IGNORECASE),
    re.compile(r'<\s*form', re.IGNORECASE),
    re.compile(r'<\s*input', re.IGNORECASE),
    re.compile(r'<\s*button', re.IGNORECASE),
    re.compile(r'<\s*base', re.IGNORECASE),
    re.compile(r'<\s*style', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'setTimeout\s*\(', re.IGNORECASE),
    re.compile(r'setInterval\s*\(', re.IGNORECASE),
    re.compile(r'Function\s*\(', re.IGNORECASE),
    re.compile(r'document\s*\.', re.IGNORECASE),
    re.compile(r'window\s*\.', re.IGNORECASE),
    re.compile(r'&#\s*x?[0-9a-fA-F]+\s*;', re.IGNORECASE),
    re.compile(r'\\u[0-9a-fA-F]{4}', re.IGNORECASE),
    re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE),
]

_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x80-\x9f]')
_DISALLOWED_CHARS = re.compile(r'[^\w\s\-.,!?@#+\(\)\[\]]')


def sanitize_input(value):
    if not isinstance(value, str):
        return ""

    if len(value) > MAX_INPUT_LENGTH:
        value = value[:MAX_INPUT_LENGTH]

    value = _CONTROL_CHARS.sub('', value)

    try:
        value = unicodedata.normalize('NFC', value)
    except (TypeError, ValueError):
        return ''

    try:
        value = value.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return ''

    for pattern in _DANGEROUS_PATTERNS:
        value = pattern.sub('', value)

    if not ALLOWED_PATTERN.match(value):
        value = _DISALLOWED_CHARS.sub('', value)

    if len(value) > MAX_INPUT_LENGTH:
        value = value[:MAX_INPUT_LENGTH]

    return value


def encode_output(value):
    if not isinstance(value, str):
        value = ""

    escaped = html.escape(str(escape(value)), quote=True)
    escaped = escaped.replace("&#x27;", "&#39;")
    escaped = escaped.replace("/", "&#x2F;")
    escaped = escaped.replace("`", "&#x60;")
    escaped = escaped.replace("(", "&#40;")
    escaped = escaped.replace(")", "&#41;")
    escaped = escaped.replace("[", "&#91;")
    escaped = escaped.replace("]", "&#93;")
    escaped = escaped.replace("\\", "&#92;")
    escaped = escaped.replace("{", "&#123;")
    escaped = escaped.replace("}", "&#125;")
    escaped = escaped.replace("+", "&#43;")
    escaped = escaped.replace("=", "&#61;")
    return escaped


def generate_nonce():
    return secrets.token_hex(32)


def validate_content_length(req):
    content_length = req.content_length
    if content_length is not None and content_length > MAX_CONTENT_LENGTH:
        return False
    return True


def _build_security_headers(response, nonce):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; "
        f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
        f"style-src 'nonce-{nonce}'; "
        f"img-src 'none'; "
        f"font-src 'none'; "
        f"connect-src 'none'; "
        f"media-src 'none'; "
        f"object-src 'none'; "
        f"child-src 'none'; "
        f"worker-src 'none'; "
        f"manifest-src 'none'; "
        f"prefetch-src 'none'; "
        f"base-uri 'none'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none'; "
        f"upgrade-insecure-requests; "
        f"block-all-mixed-content"
    )
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=(), '
        'usb=(), interest-cohort=(), accelerometer=(), gyroscope=(), '
        'magnetometer=(), ambient-light-sensor=(), autoplay=(), '
        'encrypted-media=(), picture-in-picture=(), fullscreen=(), '
        'display-capture=(), document-domain=()'
    )
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['X-DNS-Prefetch-Control'] = 'off'
    return response


def init(app):

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        try:
            if not validate_content_length(request):
                response = make_response("Request too large", 413)
                response.headers['Content-Type'] = 'text/plain; charset=utf-8'
                response.headers['X-Content-Type-Options'] = 'nosniff'
                return response

            raw_param = request.form.get("BenchmarkTest00096", "")
            if not isinstance(raw_param, str):
                raw_param = ""

            if len(raw_param) > MAX_INPUT_LENGTH:
                raw_param = raw_param[:MAX_INPUT_LENGTH]

            param = sanitize_input(raw_param)

            param_hash = hashlib.sha256(param.encode('utf-8')).hexdigest()
            _ = param_hash

            possible = "ABC"
            guess = possible[0]

            match guess:
                case 'A':
                    bar = param
                case 'B':
                    bar = 'bob'
                case 'C' | 'D':
                    bar = param
                case _:
                    bar = "bob&#39;s your uncle"

            otherarg = "static text"

            safe_bar = encode_output(bar)
            safe_otherarg = encode_output(otherarg)

            nonce = generate_nonce()

            RESPONSE = (
                f"bar is '{safe_bar}' and otherarg is '{safe_otherarg}'"
            )

            response = make_response(RESPONSE)
            response = _build_security_headers(response, nonce)

            return response

        except Exception:
            logger.exception("Unhandled error in BenchmarkTest00096_post")
            response = make_response("Internal Server Error", 500)
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['Cache-Control'] = 'no-store'
            return response