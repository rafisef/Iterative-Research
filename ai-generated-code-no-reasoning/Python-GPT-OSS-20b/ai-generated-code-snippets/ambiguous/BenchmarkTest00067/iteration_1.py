from flask import redirect, request, make_response, render_template
import base64
import urllib.parse

def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def benchmark_test_00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            'BenchmarkTest00067',
            urllib.parse.quote_plus('http://localhost:5000/'),
            max_age=180,
            secure=True,
            path=request.path,
            domain=request.host.split(':')[0]
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def benchmark_test_00067_post():
        cookie_val = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
        decoded = urllib.parse.unquote_plus(cookie_val)
        try:
            redirect_url = base64.b64decode(decoded).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            redirect_url = '/'
        return redirect(redirect_url)