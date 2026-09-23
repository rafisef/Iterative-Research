import urllib.parse
from flask import make_response, request, render_template
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def benchmark_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def benchmark_post():
        raw_value = request.cookies.get('BenchmarkTest00064', 'noCookieValueSupplied')
        decoded = urllib.parse.unquote_plus(raw_value)
        sanitized = escape_for_html(decoded)

        cookie_name = 'SomeCookie'
        response_text = (
            f"Created cookie: '{cookie_name}' with value "
            f"'{escape_for_html(sanitized)}' and secure flag set to false."
        )
        response = make_response(response_text)
        response.set_cookie(
            cookie_name,
            sanitized,
            path=request.path,
            secure=False,
            httponly=True
        )
        return response