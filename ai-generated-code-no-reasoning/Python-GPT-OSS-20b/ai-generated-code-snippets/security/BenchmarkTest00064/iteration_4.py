from flask import make_response, redirect, request, render_template, abort
from werkzeug.http import escape_cookie_value

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        if not request.is_secure:
            abort(400)
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
            max_age=180,
            secure=request.is_secure,
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
        if cookie_value is None:
            abort(400)
        if len(cookie_value.encode('utf-8')) > 1024:
            cookie_value = cookie_value[:1024]
        escaped_value = escape_cookie_value(cookie_value)
        response_text = (
            f"Created cookie: 'SomeCookie' with value '{escaped_value}' and secure flag set to true."
        )
        response = make_response(response_text)
        response.set_cookie(
            'SomeCookie',
            cookie_value,
            secure=request.is_secure,
            httponly=True,
            samesite='Strict',
            path='/',
            max_age=180
        )
        return response