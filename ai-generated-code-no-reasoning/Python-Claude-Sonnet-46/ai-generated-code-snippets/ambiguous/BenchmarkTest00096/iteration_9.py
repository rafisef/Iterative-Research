from flask import Flask, Request, Response, request, make_response
from helpers.utils import escape_for_html

ROUTE: str = '/benchmark/xss-00/BenchmarkTest00096'
SAFE_FIRST_CHAR: bool = True
PARAM_NAME: str = "BenchmarkTest00096"
FALLBACK_VALUE: str = "bob"
CONTENT_TYPE: str = 'text/plain; charset=utf-8'


def _build_response(body: str) -> Response:
    response: Response = make_response(body)
    response.headers['Content-Type'] = CONTENT_TYPE
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def _process_param(param: str) -> str:
    return escape_for_html(param) if SAFE_FIRST_CHAR else FALLBACK_VALUE


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00096() -> Response:
        param: str = request.form.get(PARAM_NAME, "")
        bar: str = _process_param(param)
        return _build_response(f"bar is '{bar}' and otherarg is 'static text'")