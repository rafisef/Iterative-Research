from flask import Flask, Response, request, make_response
from helpers.utils import escape_for_html

ROUTE: str = '/benchmark/xss-00/BenchmarkTest00096'
PARAM_NAME: str = "BenchmarkTest00096"
CONTENT_TYPE: str = 'text/plain; charset=utf-8'


def _build_response(body: str) -> Response:
    response: Response = make_response(body)
    response.headers['Content-Type'] = CONTENT_TYPE
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def init(app: Flask) -> None:

    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00096() -> Response:
        param: str = escape_for_html(request.form.get(PARAM_NAME, ""))
        return _build_response(f"bar is '{param}' and otherarg is 'static text'")