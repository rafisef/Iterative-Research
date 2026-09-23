from flask import redirect, request, make_response
from helpers.utils import escape_for_html

def init(app):
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PREFERRED_URL_SCHEME'] = 'https'

    @app.before_request
    def enforce_https():
        if not request.is_secure and request.host:
            return redirect(request.url.replace("http://", "https://"), code=301)

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none';"
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        param = request.form.get("BenchmarkTest00096", "")
        if not isinstance(param, str):
            param = str(param)
        param = param[:4096]
        possible = "ABC"
        guess = possible[0]
        if guess == 'A':
            bar = param
        elif guess == 'B':
            bar = 'bob'
        elif guess in ('C', 'D'):
            bar = param
        else:
            bar = "bob's your uncle"
        bar_safe = escape_for_html(bar)
        otherarg_safe = escape_for_html("static text")
        response_text = f"bar is '{bar_safe}' and otherarg is '{otherarg_safe}'"
        return make_response(response_text, 200, {"Content-Type": "text/html; charset=utf-8"})