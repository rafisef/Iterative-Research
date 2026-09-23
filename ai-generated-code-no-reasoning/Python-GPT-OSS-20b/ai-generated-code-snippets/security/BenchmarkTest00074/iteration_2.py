from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse

def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            'BenchmarkTest00074',
            '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path
        )
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        cookie_val = request.cookies.get('BenchmarkTest00074', 'noCookieValueSupplied')
        decoded = urllib.parse.unquote_plus(cookie_val)
        safe_output = escape_for_html(decoded)
        response = make_response(safe_output)
        response.mimetype = 'text/plain'
        return response