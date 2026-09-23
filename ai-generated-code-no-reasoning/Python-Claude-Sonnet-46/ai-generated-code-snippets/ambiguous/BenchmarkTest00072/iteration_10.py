from flask import request, make_response, render_template, session
from helpers.utils import escape_for_html

_COOKIE_NAME = "BenchmarkTest00072"
_ROUTE = "/benchmark/trustbound-00/BenchmarkTest00072"
_SESSION_KEY = "benchmark_test_00072_key"
_SESSION_VALUE = "12345"
_COOKIE_MAX_AGE = 180
_COOKIE_USER_ID = "my-user-id"
_RESPONSE_TEMPLATE = "web/trustbound-00/BenchmarkTest00072.html"


def _build_cookie_response():
    response = make_response(render_template(_RESPONSE_TEMPLATE))
    response.set_cookie(
        _COOKIE_NAME,
        _COOKIE_USER_ID,
        max_age=_COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Strict",
        path=request.path,
        domain="localhost",
    )
    return response


def _build_session_response():
    session[_SESSION_KEY] = _SESSION_VALUE
    escaped_key = escape_for_html(_SESSION_KEY)
    escaped_value = escape_for_html(_SESSION_VALUE)
    return f"Item: '{escaped_key}' with value: {escaped_value} saved in session.", 200


def init(app):
    app.add_url_rule(_ROUTE, endpoint="benchmark_get_00072", view_func=_build_cookie_response, methods=["GET"])
    app.add_url_rule(_ROUTE, endpoint="benchmark_post_00072", view_func=_build_session_response, methods=["POST"])