import io
import urllib.parse

from flask import make_response, render_template, request

import helpers.utils

COOKIE_MAX_AGE = 180
BENCHMARK_COOKIE_NAME = 'BenchmarkTest00064'
OUTPUT_COOKIE_NAME = 'SomeCookie'


def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            BENCHMARK_COOKIE_NAME,
            'whatever',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        raw_param = request.cookies.get(BENCHMARK_COOKIE_NAME, 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(raw_param)
        bar = helpers.utils.escape_for_html(param)

        if isinstance(bar, str):
            raw = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            raw = bar.read(1000)
        else:
            raw = b''

        cookie_value = raw.decode('utf-8')
        escaped_value = helpers.utils.escape_for_html(cookie_value)
        response_body = (
            f"Created cookie: '{OUTPUT_COOKIE_NAME}' with value "
            f"'{escaped_value}' and secure flag set to false."
        )

        response = make_response(response_body)
        response.set_cookie(
            OUTPUT_COOKIE_NAME,
            cookie_value,
            path=request.path,
            secure=False,
            httponly=True
        )

        return response