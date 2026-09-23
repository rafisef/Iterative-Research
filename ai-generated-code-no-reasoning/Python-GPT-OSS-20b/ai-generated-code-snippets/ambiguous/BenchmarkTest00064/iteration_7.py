import urllib.parse
from flask import Flask, request, render_template, make_response, escape

def init(app: Flask):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET', 'POST'])
    def benchmark():
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
        decoded = urllib.parse.unquote_plus(raw_cookie)
        safe_val = escape(decoded)
        new_cookie_name = 'SomeCookie'
        msg = f"Created cookie: '{new_cookie_name}' with value '{safe_val}' and secure flag set to false."
        resp = make_response(msg)
        resp.set_cookie(
            new_cookie_name,
            urllib.parse.quote_plus(decoded),
            path=request.path,
            secure=False,
            httponly=True,
            samesite='Strict'
        )
        return resp