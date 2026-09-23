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
TEMPLATE_PATH = f'web/weakrand-00/{BENCHMARK_TEST_ID}.html'


def _build_bar(param: str) -> str:
    full_string = f'{PREFIX}{param}abcd'
    start = len(PREFIX)
    end = len(full_string) - SUFFIX_LEN
    return full_string[start:end] if end > start else ''


def _set_benchmark_cookie(response: make_response, path: str) -> None:
    response.set_cookie(
        BENCHMARK_TEST_ID,
        'whatever',
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost',
    )


def _get_param_from_cookie() -> str:
    raw_cookie = request.cookies.get(BENCHMARK_TEST_ID, 'noCookieValueSupplied')
    return urllib.parse.unquote_plus(raw_cookie)


def _is_valid_session() -> bool:
    stored = mysession.get(COOKIE_NAME)
    provided = request.cookies.get(COOKIE_NAME)
    return bool(stored and provided and secrets.compare_digest(stored, provided))


def _authenticate_or_remember() -> str:
    if _is_valid_session():
        return f'Welcome back: {USER}<br/>'

    token = secrets.token_hex(16)
    mysession[COOKIE_NAME] = token
    return (
        f'{USER} has been remembered with cookie: '
        f'{COOKIE_NAME} whose value is: {token}<br/>'
    )


def init(app) -> None:

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template(TEMPLATE_PATH))
        _set_benchmark_cookie(response, request.path)
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00025_post():
        param = _get_param_from_cookie()
        _build_bar(param)
        return _authenticate_or_remember()