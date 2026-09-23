import re
import urllib.parse
from flask import request, make_response, render_template
import helpers.db_sqlite

COOKIE_NAME = 'BenchmarkTest00011'
ROUTE = '/benchmark/sqli-00/BenchmarkTest00011'
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'
SQL_QUERY = 'SELECT username FROM USERS WHERE password = ?'
MAX_PARAM_LENGTH = 256
MIN_PARAM_LENGTH = 1
ALLOWED_PARAM_PATTERN = re.compile(r'^[\w@.\-]+$')
COOKIE_MAX_AGE = 180
TEMPLATE_PATH = 'web/sqli-00/BenchmarkTest00011.html'


def _build_cookie_response(template_path: str, cookie_value: str, path: str):
    response = make_response(render_template(template_path))
    response.set_cookie(
        COOKIE_NAME,
        cookie_value,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost'
    )
    return response


def _is_valid_param(param: str) -> bool:
    return bool(
        param
        and MIN_PARAM_LENGTH <= len(param) <= MAX_PARAM_LENGTH
        and ALLOWED_PARAM_PATTERN.match(param)
    )


def _execute_query(param: str) -> tuple:
    con = helpers.db_sqlite.get_connection()
    try:
        cur = con.cursor()
        cur.execute(SQL_QUERY, (param,))
        return helpers.db_sqlite.results(cur, SQL_QUERY), None
    except Exception as exc:
        return None, exc
    finally:
        con.close()


def _get_sanitised_param() -> str:
    raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    return urllib.parse.unquote_plus(raw_cookie).strip()


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00011_get():
        return _build_cookie_response(TEMPLATE_PATH, 'bar', request.path)

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00011_post():
        param = _get_sanitised_param()

        if not _is_valid_param(param):
            return make_response('Invalid input', 400)

        result, error = _execute_query(param)
        if error is not None:
            return make_response('An error occurred', 500)

        return result