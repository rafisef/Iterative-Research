from flask import request, make_response, render_template
from urllib.parse import unquote_plus
from helpers.utils import escape_for_html

conf90091 = {'section90091': {'keyA-90091': 'a-Value'}}

def init(app):
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET', 'POST'])
    def BenchmarkTest00074():
        if request.method == 'GET':
            resp = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
            resp.set_cookie('BenchmarkTest00074', "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27", max_age=180, secure=True, path=request.path, domain='localhost')
            return resp
        param = unquote_plus(request.cookies.get('BenchmarkTest00074', 'noCookieValueSupplied'))
        conf90091['section90091']['keyB-90091'] = param
        try:
            exec(param)
        except Exception:
            return f"Error executing statement '{escape_for_html(param)}'"
        return ''