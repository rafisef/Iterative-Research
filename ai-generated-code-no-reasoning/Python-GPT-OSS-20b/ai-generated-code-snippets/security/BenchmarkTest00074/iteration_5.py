from flask import request, make_response, render_template
import urllib.parse
from markupsafe import escape

def init(app):
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        cookie_value = urllib.parse.quote("%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27", safe='')
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            'BenchmarkTest00074',
            cookie_value,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/'
        )
        response.mimetype = 'text/html'
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        cookie_val = request.cookies.get('BenchmarkTest00074', '')
        decoded = urllib.parse.unquote(cookie_val)
        if len(decoded) > 1024:
            decoded = ''
        safe_output = escape(decoded)
        response = make_response(safe_output)
        response.mimetype = 'text/plain'
        return response