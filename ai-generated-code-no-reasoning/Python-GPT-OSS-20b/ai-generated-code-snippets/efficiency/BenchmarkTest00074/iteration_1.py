from flask import request, make_response, render_template
import urllib.parse
import configparser
from helpers.utils import escape_for_html

conf90091 = configparser.ConfigParser()
conf90091.add_section('section90091')
conf90091.set('section90091', 'keyA-90091', 'a-Value')

def init(app):
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            'BenchmarkTest00074',
            '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        RESPONSE = ''
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00074', 'noCookieValueSupplied'))
        conf90091.set('section90091', 'keyB-90091', param)
        bar = conf90091.get('section90091', 'keyB-90091')
        try:
            exec(bar)
        except Exception:
            RESPONSE += f"Error executing statement '{escape_for_html(bar)}'"
        return RESPONSE