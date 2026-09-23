from flask import make_response, abort, request, render_template
import re
from werkzeug.http import escape_cookie_value
from markupsafe import escape

def init(app):
    csrf_re = re.compile(r'^[\x20-\x7E]{1,1024}$')

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
            'X-DNS-Prefetch-Control': 'off'
        })
        return response

    @app.after_request
    def apply_security_headers(response):
        return set_security_headers(response)

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        if not request.is_secure:
            abort(400)
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
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
        cookie_value = request.cookies.get('BenchmarkTest00064')
        if not cookie_value or not csrf_re.match(cookie_value):
            abort(400)
        escaped_value = escape_cookie_value(cookie_value)
        response_text = (
            f"Created cookie: 'SomeCookie' with value '{escape(cookie_value)}' "
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
        return response