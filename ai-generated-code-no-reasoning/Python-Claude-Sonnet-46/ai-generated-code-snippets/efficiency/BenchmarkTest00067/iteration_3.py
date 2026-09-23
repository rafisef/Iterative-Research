from flask import redirect, request, make_response, render_template
from urllib.parse import unquote_plus
from base64 import b64encode, b64decode

def init(app):
    cookie_name = 'BenchmarkTest00067'
    cookie_value = 'http%3A%2F%2Flocalhost%3A5000%2F'
    route = '/benchmark/redirect-00/BenchmarkTest00067'

    @app.route(route, methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(cookie_name, cookie_value,
            max_age=180,
            secure=True,
            path=route,
            domain='localhost')
        return response

    @app.route(route, methods=['POST'])
    def BenchmarkTest00067_post():
        param = unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))
        return redirect(param)