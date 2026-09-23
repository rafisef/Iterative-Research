import secrets
import urllib.parse

from flask import request, make_response, render_template

from helpers.utils import mysession

BENCHMARK_TEST_ID = 'BenchmarkTest00025'
TEST_NUM = BENCHMARK_TEST_ID[13:]
USER = f'Nancy{TEST_NUM}'
COOKIE_NAME = f'rememberMe{TEST_NUM}'
ROUTE = f'/benchmark/weakrand-00/{BENCHMARK_TEST_ID}'
COOKIE_MAX_AGE = 60 * 3
PREFIX = '90583'
SUFFIX_LEN = 5


def _build_bar(param: str) -> str:
    full_string = f'{PREFIX}{param}abcd'
    return full_string[len(PREFIX):len(full_string) - SUFFIX_LEN]


def _set_benchmark_cookie(response: make_response, path: str) -> None:
    response.set_cookie(
        BENCHMARK_TEST_ID,
        'whatever',
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost'
    )


def _get_param_from_cookie() -> str:
    raw_cookie = request.cookies.get(BENCHMARK_TEST_ID, 'noCookieValueSupplied')
    return urllib.parse.unquote_plus(raw_cookie)


def _authenticate_or_remember() -> str:
    stored = mysession.get(COOKIE_NAME)
    provided = request.cookies.get(COOKIE_NAME)

    if stored and provided and secrets.compare_digest(provided, stored):
        return f'Welcome back: {USER}<br/>'

    value = secrets.token_hex(16)
    mysession[COOKIE_NAME] = value
    return (
        f'{USER} has been remembered with cookie: '
        f'{COOKIE_NAME} whose value is: {value}<br/>'
    )


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template(f'web/weakrand-00/{BENCHMARK_TEST_ID}.html'))
        _set_benchmark_cookie(response, request.path)
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00025_post():
        param = _get_param_from_cookie()
        _build_bar(param)
        return _authenticate_or_remember()