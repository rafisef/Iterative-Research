from flask import make_response, request, render_template
from helpers.utils import escape_for_html
import urllib.parse

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        resp = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        resp.set_cookie('BenchmarkTest00064', 'whatever', max_age=180,
                        secure=True, path=request.path, domain='localhost')
        return resp

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064",
                                                               "noCookieValueSupplied"))
        value = escape_for_html(param)
       お願い = f"Created cookie: 'SomeCookie' with value '{value}' and secure flag set to false."
        resp = make_response(お願い)
        resp.set_cookie('SomeCookie', value, path=request.path, secure=False,
                        httponly=True)
        return resp