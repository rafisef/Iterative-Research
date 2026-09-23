import urllib.parse
from flask import Flask, request, render_template, make_response, escape

def init(app: Flask) -> None:
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET', 'POST'])
    def benchmark_test00064():
        if request.method == 'GET':
            response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
            response.set_cookie(
                'BenchmarkTest00064',
                'whatever',
                max_age=180,
                secure=True,
                path=request.path,
                httponly=True,
                samesite='Lax'
            )
            return response

        raw_cookie = request.cookies.get('BenchmarkTest00064', '')
        decoded = urllib.parse.unquote_plus(raw_cookie)
        safe_value = escape(decoded)

        response = make_response(
            f"Created cookie: 'SomeCookie' with value '{safe_value}' and secure flag set to false."
        )
        response.set_cookie(
            'SomeCookie',
            urllib.parse.quote_plus(decoded),
            path=request.path,
            secure=False,
            httponly=True,
            samesite='Strict'
        )
        return response