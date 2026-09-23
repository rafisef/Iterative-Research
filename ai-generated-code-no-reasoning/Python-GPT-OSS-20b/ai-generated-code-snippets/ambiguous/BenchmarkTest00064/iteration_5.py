import urllib.parse
from flask import make_response, request, render_template, current_app

def init(app):
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
                domain=request.host.split(':')[0],
                httponly=True,
                samesite='Lax'
            )
            return resp

        raw = request.cookies.get('BenchmarkTest00064', '')
        decoded = urllib.parse.unquote_plus(raw)
        sanitized = current_app.escape_for_html(decoded)

        name = 'SomeCookie'
        msg = f"Created cookie: '{name}' with value '{sanitized}' and secure flag set to false."
        resp = make_response(msg)
        resp.set_cookie(
            name,
            urllib.parse.quote_plus(decoded),
            path=request.path,
            secure=False,
            httponly=True,
            samesite='Strict'
        )
        return resp