from flask import Flask, redirect, request, make_response, render_template
import base64, urllib.parse

def init(app: Flask):
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET', 'POST'])
    def benchmark_test_00067():
        if request.method == 'GET':
            resp = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
            resp.set_cookie(
                'BenchmarkTest00067',
                urllib.parse.quote_plus('http://localhost:5000/'),
                max_age=180,
                secure=True,
                path=request.path,
                domain=request.host.split(':')[0],
                httponly=True,
                samesite='Strict'
            )
            return resp

        cookie_val = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
        decoded = urllib.parse.unquote_plus(cookie_val)
        try:
            redirect_url = base64.b64decode(decoded).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            redirect_url = '/'
        return redirect(redirect_url)