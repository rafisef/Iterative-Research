from flask import redirect, request, make_response, render_template
from urllib.parse import unquote_plus

COOKIE_NAME = 'BenchmarkTest00067'
COOKIE_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
ROUTE = '/benchmark/redirect-00/BenchmarkTest00067'
COOKIE_SETTINGS = {
    'max_age': 180,
    'secure': True,
    'path': ROUTE,
    'domain': 'localhost'
}

def init(app):
    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(COOKIE_NAME, COOKIE_VALUE, **COOKIE_SETTINGS)
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00067_post():
        return redirect(unquote_plus(request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")))