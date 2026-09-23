from flask import Flask, abort, render_template, request, session
import hmac
import os
import secrets
import time
from datetime import timedelta

def init(app: Flask) -> None:
    app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(64))
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="secure_session",
        SESSION_COOKIE_PATH="/",
        SESSION_COOKIE_DOMAIN=None,
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=180),
        MAX_CONTENT_LENGTH=1024 * 1024,
        PREFERRED_URL_SCHEME="https",
        SERVER_NAME=os.getenv("SERVER_NAME"),
    )

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Download-Options"] = "noopen"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["GET"])
    def benchmark_get():
        token = secrets.token_urlsafe(32)
        session.permanent = True
        session["BenchmarkTest00025_token"] = {"value": token, "timestamp": time.time()}
        return render_template(
            "web/weakrand-00/BenchmarkTest00025.html", csrf_token=token
        )

    @app.route("/benchmark/weakrand-00/BenchmarkTest00025", methods=["POST"])
    def benchmark_post():
        stored = session.get("BenchmarkTest00025_token")
        csrf_token = request.headers.get("X-CSRFToken")
        if not stored or not csrf_token:
            abort(400)
        token, timestamp = stored["value"], stored["timestamp"]
        if time.time() - timestamp > 180:
            session.pop("BenchmarkTest00025_token", None)
            abort(403)
        if not hmac.compare_digest(token, csrf_token):
            abort(403)
        session.pop("BenchmarkTest00025_token", None)
        return "Welcome back: Nancy"