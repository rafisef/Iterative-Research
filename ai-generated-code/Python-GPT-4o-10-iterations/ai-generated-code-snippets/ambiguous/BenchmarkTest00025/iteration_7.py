from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, mysession
import random
import urllib.parse

def init(app):

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_test_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025', 'whatever',
            max_age=180,  # 60 * 3
            secure=True,
            path=request.path,
            domain='localhost',
            httponly=True
        )
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_test_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
        )
        bar = param[1:-4] if len(param) > 5 else ''

        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate(0, 1))[2:]

        if mysession.get(cookie) == request.cookies.get(cookie):
            response_msg = f'Welcome back: {escape_for_html(user)}<br/>'
        else:
            mysession[cookie] = value
            response_msg = (
                f'{escape_for_html(user)} has been remembered with cookie: '
                f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
            )

        return response_msg