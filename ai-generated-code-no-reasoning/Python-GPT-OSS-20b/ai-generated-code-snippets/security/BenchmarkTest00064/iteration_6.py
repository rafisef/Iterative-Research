from flask import make_response, abort, request, render_template
from werkzeug.http import escape_cookie_value
from markupsafe import escape

def init(app):
    def set_security_headers(response, content_type):
        response.headers['Content-Type'] = content_type
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Referrer-Policy'] = 'origin-when-cross-origin'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        return response

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
        return set_security_headers(response, 'text/html; charset=utf-8')

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        if not request.is_secure:
            abort(400)
        cookie_value = request.cookies.get('BenchmarkTest00064')
        if cookie_value is None:
            abort(400)
        if len(cookie_value) > 1024:
            cookie_value = cookie_value[:1024]
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
        return set_security_headers(response, 'text/plain; charset=utf-8')