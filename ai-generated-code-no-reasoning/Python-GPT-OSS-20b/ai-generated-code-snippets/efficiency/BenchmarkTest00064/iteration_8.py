from flask import make_response, request, render_template
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET', 'POST'])
    def BenchmarkTest00064():
        path = request.path
        if request.method == 'GET':
            resp = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
            resp.set_cookie('BenchmarkTest00064', 'whatever', max_age=180, secure=True, path=path, domain='localhost')
            return resp
        cookies = request.cookies
        cookie = cookies.get('BenchmarkTest00064', 'noCookieValueSupplied')
        escaped = escape_for_html(unquote_plus(cookie))
        resp = make_response(f"Created cookie: 'SomeCookie' with value '{escaped}' and secure flag set to false.")
        resp.set_cookie('SomeCookie', escaped, path=path, secure=False, httponly=True)
        return resp