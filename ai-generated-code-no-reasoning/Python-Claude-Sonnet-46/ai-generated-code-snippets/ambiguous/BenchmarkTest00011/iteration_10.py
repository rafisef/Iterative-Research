import re
import urllib.parse
import logging
from contextlib import contextmanager
from http import HTTPStatus
from typing import Generator, Optional

from flask import request, make_response, render_template, Response
import helpers.db_sqlite

COOKIE_NAME = "BenchmarkTest00011"
ROUTE = "/benchmark/sqli-00/BenchmarkTest00011"
DEFAULT_COOKIE_VALUE = "noCookieValueSupplied"
SQL_QUERY = "SELECT username FROM USERS WHERE password = ?"
MAX_PARAM_LENGTH = 256
MIN_PARAM_LENGTH = 1
ALLOWED_PARAM_PATTERN = re.compile(r"^[\w@.\-]+$")
COOKIE_MAX_AGE = 180
TEMPLATE_PATH = "web/sqli-00/BenchmarkTest00011.html"
COOKIE_DEFAULTS = {
    "max_age": COOKIE_MAX_AGE,
    "secure": True,
    "httponly": True,
    "samesite": "Strict",
    "domain": "localhost",
}

logger = logging.getLogger(__name__)


@contextmanager
def _db_connection() -> Generator:
    con = helpers.db_sqlite.get_connection()
    try:
        yield con
    finally:
        try:
            con.close()
        except Exception:
            logger.debug("Failed to close database connection", exc_info=True)


def _build_cookie_response(
    template_path: str,
    cookie_value: str,
    path: str,
) -> Response:
    response = make_response(render_template(template_path))
    response.set_cookie(COOKIE_NAME, cookie_value, path=path, **COOKIE_DEFAULTS)
    return response


def _is_valid_param(param: object) -> bool:
    return (
        isinstance(param, str)
        and MIN_PARAM_LENGTH <= len(param) <= MAX_PARAM_LENGTH
        and bool(ALLOWED_PARAM_PATTERN.match(param))
    )


def _execute_query(param: str) -> tuple[Optional[object], Optional[Exception]]:
    try:
        with _db_connection() as con:
            cur = con.cursor()
            cur.execute(SQL_QUERY, (param,))
            return helpers.db_sqlite.results(cur, SQL_QUERY), None
    except Exception as exc:
        logger.error("Query execution failed", exc_info=True)
        return None, exc


def _get_sanitised_param() -> str:
    raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    if not isinstance(raw_cookie, str):
        return DEFAULT_COOKIE_VALUE
    return urllib.parse.unquote_plus(raw_cookie).strip()


def _handle_get() -> Response:
    return _build_cookie_response(TEMPLATE_PATH, "bar", request.path)


def _handle_post() -> Response:
    param = _get_sanitised_param()

    if not _is_valid_param(param):
        logger.warning("Invalid input received for cookie param")
        return make_response("Invalid input", HTTPStatus.BAD_REQUEST)

    result, error = _execute_query(param)

    if error is not None:
        return make_response("An error occurred", HTTPStatus.INTERNAL_SERVER_ERROR)

    if result is None:
        return make_response("No results found", HTTPStatus.NOT_FOUND)

    return result


def init(app) -> None:
    @app.route(ROUTE, methods=["GET"])
    def benchmark_test_00011_get() -> Response:
        return _handle_get()

    @app.route(ROUTE, methods=["POST"])
    def benchmark_test_00011_post() -> Response:
        return _handle_post()