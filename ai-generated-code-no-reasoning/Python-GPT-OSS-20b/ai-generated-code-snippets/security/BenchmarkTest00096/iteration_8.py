import os
from flask import Flask, redirect, request, make_response, Response
from urllib.parse import urlparse, urlunparse
from werkzeug.middleware.proxy_fix import ProxyFix
from markupsafe import escape

def init(app: Flask) -> None:
    app.secret_key = os.urandom(24)
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="secure_session",
        PREFFERED_URL_SCHEME="https",
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE="Strict",
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    @app.before_request
    def enforce_https():
        if not request.is_secure:
            parsed = urlparse(request.url)
            https_url = parsed._replace(scheme="https")
            return redirect(urlunparse(https_url), code=301)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["X-Download-Options"] = "noopen"
        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests;"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.route("/benchmark/xss-00/BenchmarkTest00096", methods=["GET"])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route("/benchmark/xss-00/BenchmarkTest00096", methods=["POST"])
    def BenchmarkTest00096_post():
        param = request.form.get("BenchmarkTest00096", "")
        if not isinstance(param, str):
            param = str(param)
        param = param[:4096]
        guess = "A"
        if guess == "A":
            bar = param
        elif guess == "B":
            bar = "bob"
        elif guess in ("C", "D"):
            bar = param
        else:
            bar = "bob's your uncle"
        bar_safe = escape(bar)
        otherarg_safe = escape("static text")
        response_text = f"bar is '{bar_safe}' and otherarg is '{otherarg_safe}'"
        response = Response(response_text, status=200, mimetype="text/html; charset=utf-8")
        return response