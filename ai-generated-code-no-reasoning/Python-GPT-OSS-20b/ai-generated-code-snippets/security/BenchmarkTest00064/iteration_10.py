from flask import make_response, abort, request, render_template, session
import re
import secrets
import os
from werkzeug.http import escape_cookie_value
from markupsafe import escape

def init(app):
    app.secret_key = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_PATH='/',
        PERMANENT_SESSION_LIFETIME=180
    )
    csrf_regex = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
    def set_security_headers(response):
        response.headers.setdefault('Content-Type', response.mimetype)
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': ("default-src 'self'; script-src 'self'; object-src 'none'; "
                                        "base-uri 'self'; form-action 'self'; upgrade-insecure-requests"),
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'Cache-Control': 'no-store, no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Permitted-Cross-Domain-Policies': 'none',
            'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=()',
            'X-DNS-Prefetch-Control': 'off',
            'X-XSS-Protection': '1; mode=block'
        })
        return response
    @app.after_request
    def apply_security_headers(response):
        return set_security_headers(response)
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        if not request.is_secure:
            abort(400)
        token = secrets.token_urlsafe(32)
        session['BenchmarkTest00064_csrf'] = token
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            token,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/'
        )
        return response
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        if not request.is_secure:
            abort(400)
        cookie_token = request.cookies.get('BenchmarkTest00064')
        session_token = session.get('BenchmarkTest00064_csrf')
        if not cookie_token or not session_token or cookie_token != session_token:
            abort(400)
        if not csrf_regex.match(cookie_token):
            abort(400)
        escaped_value = escape_cookie_value(cookie_token)
        response_text = (
            f"Created cookie: 'SomeCookie' with value '{escape(cookie_token)}' "
            f"and secure flag set to true."
        )
        response = make_response(response_text)
        response.set_cookie(
            'SomeCookie',
            escaped_value,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/',
            max_age=180
        )
        session.pop('BenchmarkTest00064_csrf', None)
        return response