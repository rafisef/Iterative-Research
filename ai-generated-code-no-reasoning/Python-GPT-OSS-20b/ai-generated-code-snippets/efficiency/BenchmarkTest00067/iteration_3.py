from flask import Flask, redirect, request, make_response, render_template
from urllib.parse import unquote

def init(app: Flask):
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET', 'POST'])
    def benchmark():
        if request.methodLIB == 'GET':
            resp = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
            resp.set_cookie(
                'BenchmarkTest00067',
                'http%3A%2F%2Flocalhost%3A5000%2F',
                max_age=180,
                secure=True,
                path=request.path,
                domain='localhost',
            )
            return resp
        return redirect(unquote(request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')))