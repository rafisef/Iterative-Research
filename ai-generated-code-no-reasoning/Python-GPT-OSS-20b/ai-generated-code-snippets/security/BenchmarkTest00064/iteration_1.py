from flask import make_response, redirect, request, render_template, url_for

from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain=request.host.split(':')[0]
        )
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        cookie_value = request.cookies.get('BenchmarkTest00064', 'noCookieValueSupplied')
        escaped_value = escape_for_html(cookie_value)
        decoded_value = escaped_value.encode('utf-8')
        if len(decoded_value) > 1024:
            decoded_value = decoded_value[:1024]
        value = decoded_value.decode('utf-8')
        response_text = (
            f"Created cookie: 'SomeCookie' with value '{escape_for_html(value)}' and secure flag set to false."
        )
        response = make_response(response_text)
        response.set_cookie(
            'SomeCookie',
            value,
            path=request.path,
            secure=False,
            httponly=True,
            samesite='Lax'
        )
        return response