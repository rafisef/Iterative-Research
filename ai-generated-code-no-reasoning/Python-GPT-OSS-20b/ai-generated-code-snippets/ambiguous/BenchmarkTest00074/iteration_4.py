from flask import make_response, request, render_template
import urllib.parse
from helpers.utils import escape_for_html

def init(app):
    cookie_name = 'BenchmarkTest00074'

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET', 'POST'])
    def benchmark_test_00074():
        if request.method == 'GET':
            resp = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
            resp.set_cookie(
                cookie_name,
                "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27",
                max_age=180,
                secure=request.is_secure,
                path=request.path,
                domain=request.host.split(':')[0],
                samesite='Lax'
            )
            return resp
        param = request.cookies.get(cookie_name, 'noCookieValueSupplied')
        decoded = urllib.parse.unquote_plus(param)
        return f"Received code: {escape_for_html(decoded)}"