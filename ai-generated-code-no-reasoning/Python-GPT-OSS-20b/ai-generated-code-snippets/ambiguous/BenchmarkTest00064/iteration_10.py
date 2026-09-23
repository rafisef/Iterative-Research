import urllib.parse
from flask import Flask, request, render_template, make_response, escape

def init(app: Flask) -> None:
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET', 'POST'])
    def benchmark_test00064():
        if request.method == 'GET':
            resp = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
            resp.set_cookie(
                'BenchmarkTest00064',
                'whatever',
                max_age=180,
                secure=True,
                path=request.path,
                httponly=True,
                samesite='Lax'
            )
            return resp

        raw_cookie = request.cookies.get('BenchmarkTest00064', '')
        safe_value = escape(raw_cookie)

        resp = make_response(
            f"Created cookie: 'SomeCookie' with value '{safe_value}' and secure flag set to true."
        )
        resp.set_cookie(
            'SomeCookie',
            urllib.parse.quote_plus(raw_cookie),
            path=request.path,
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        return resp