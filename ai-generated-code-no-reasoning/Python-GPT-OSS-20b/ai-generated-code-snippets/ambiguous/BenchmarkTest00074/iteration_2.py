from flask import make_response, request, render_template
import urllib.parse
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def benchmark_test_00074():
        resp = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        resp.set_cookie(
            'BenchmarkTest00074',
            '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=180,
            secure=request.is_secure,
            path=request.path,
            domain=request.host.split(':')[0],
            samesite='Lax'
        )
        return resp

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def benchmark_test_00074_post():
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00074', 'noCookieValueSupplied'))
        return f"Received code: {escape_for_html(param)}"