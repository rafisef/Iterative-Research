from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import io

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        resp = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        resp.set_cookie('BenchmarkTest00064', 'whatever',
                        max_age=180, secure=True,
                        path=request.path, domain='localhost')
        return resp

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
        bar = escape_for_html(param)
        input_bytes = bar.encode('utf-8') if isinstance(bar, str) else bar.read(1000)
        value = input_bytes.decode('utf-8')
        resp_text = f"Created cookie: 'SomeCookie' with value '{escape_for_html(value)}' and secure flag set to false."
        resp = make_response(resp_text)
        resp.set_cookie('SomeCookie', value, path=request.path, secure=False, httponly=True)
        return resp