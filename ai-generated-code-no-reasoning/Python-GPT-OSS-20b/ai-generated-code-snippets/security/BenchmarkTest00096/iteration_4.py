from flask import Flask, redirect, request, make_response, escape
from urllib.parse import urlparse, urlunparse

def init(app: Flask) -> None:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        PREFERRED_URL_SCHEME='https',
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE='Strict',
    )

    @app.before_request
    def enforce_https():
        if not request.is_secure:
            parsed = urlparse(request.url)
            https_url = parsed._replace(scheme='https')
            return redirect(urlunparse(https_url), code=301)

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['X-Download-Options'] = 'noopen'
        response.headers['X-DNS-Prefetch-Control'] = 'off'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none';"
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        param = request.form.get('BenchmarkTest00096', '')
        if not isinstance(param, str):
            param = str(param)
        param = param[:4096]
        guess = 'A'
        if guess == 'A':
            bar = param
        elif guess == 'B':
            bar = 'bob'
        elif guess in ('C', 'D'):
            bar = param
        else:
            bar = "bob's your uncle"
        bar_safe = escape(bar)
        otherarg_safe = escape('static text')
        response_text = f"bar is '{bar_safe}' and otherarg is '{otherarg_safe}'"
        return make_response(response_text, 200, {'Content-Type': 'text/html; charset=utf-8'})