from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            'BenchmarkTest00074',
            '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        param = request.cookies.get('BenchmarkTest00074', 'noCookieValueSupplied')
        try:
            decoded = request.cookies.get('BenchmarkTest00074')
            if decoded is None:
                decoded = 'noCookieValueSupplied'
            decoded = decoded.replace('%27', "'").replace('+', ' ')
        except Exception:
            decoded = 'noCookieValueSupplied'

        safe_output = escape_for_html(decoded)
        response = make_response(safe_output)
        response.mimetype = 'text/plain'
        return response