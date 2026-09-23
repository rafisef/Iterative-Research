from flask import redirect, url_for, request, make_response, render_template, current_app
from helpers.utils import escape_for_html, mysession
import random
import secrets
import urllib.parse

def init(app: "Flask") -> None:
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_test_00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025',
            'whatever',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_test_00025_post():
        response_body = ""
        cookie_value = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
        param = urllib.parse.unquote_plus(cookie_value)
        superstring = f'90583{param}abcd'
        bar = superstring[5:-5]
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie_name = f'rememberMe{num}'
        value = secrets.token_urlsafe(16)
        if cookie_name in mysession and request.cookies.get(cookie_name) == mysession[cookie_name]:
            response_body += f'Welcome back: {escape_for_html(user)}<br/>'
        else:
            mysession[cookie_name] = value
            response_body += (
                f'{escape_for_html(user)} has been remembered with cookie: '
                f'{escape_for_html(cookie_name)} whose value is: '
                f'{escape_for_html(mysession[cookie_name])}<br/>'
            )
        return response_body