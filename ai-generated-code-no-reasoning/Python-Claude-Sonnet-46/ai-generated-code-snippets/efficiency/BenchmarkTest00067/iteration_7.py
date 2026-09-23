from flask import redirect, request, make_response, render_template
from urllib.parse import unquote_plus

COOKIE_NAME = 'BenchmarkTest00067'
COOKIE_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
DECODED_COOKIE_VALUE = unquote_plus(COOKIE_VALUE)
ROUTE = '/benchmark/redirect-00/BenchmarkTest00067'
COOKIE_SETTINGS = {
    'max_age': 180,
    'secure': True,
    'path': ROUTE,
    'domain': 'localhost'
}
DEFAULT_REDIRECT = "noCookieValueSupplied"
_decode_cache = {COOKIE_VALUE: DECODED_COOKIE_VALUE}

def _get_decoded(raw):
    result = _decode_cache.get(raw)
    if result is None:
        result = unquote_plus(raw)
        _decode_cache[raw] = result
    return result

def init(app):
    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00067():
        if request.method == 'GET':
            response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
            response.set_cookie(COOKIE_NAME, COOKIE_VALUE, **COOKIE_SETTINGS)
            return response
        raw = request.cookies.get(COOKIE_NAME)
        if raw is None:
            return redirect(DEFAULT_REDIRECT)
        return redirect(_get_decoded(raw))