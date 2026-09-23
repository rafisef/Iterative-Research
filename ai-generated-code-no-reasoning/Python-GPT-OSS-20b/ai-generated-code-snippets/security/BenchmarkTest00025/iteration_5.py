from flask import Flask, redirect, url_for, request, make_response, render_template, session, abort
import secrets
import os
from datetime import timedelta

def init(app: Flask) -> None:
    app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(64))
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='Strict',
        PERMANENT_SESSION_LIFETIME=timedelta(seconds=180),
    )

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Download-Options'] = 'noopen'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_get():
        token = secrets.token_urlsafe(32)
        session.permanent = True
        session['BenchmarkTest00025_token'] = token
        return render_template('web/weakrand-00/BenchmarkTest00025.html', csrf_token=token)

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_post():
        session_token = session.get('BenchmarkTest00025_token')
        csrf_token = request.headers.get('X-CSRFToken')
        if not (session_token and csrf_token and csrf_token == session_token):
            abort(403)
        session.pop('BenchmarkTest00025_token', None)
        return "Welcome back: Nancy"