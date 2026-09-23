from flask import Flask, redirect, url_for, request, make_response, render_template, session, abort
from werkzeug.utils import escape
import secrets
from datetime import timedelta

def init(app: Flask) -> None:
    app.secret_key = secrets.token_urlsafe(64)
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
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_get():
        token = secrets.token_urlsafe(32)
        session['BenchmarkTest00025_token'] = token
        session.permanent = True
        resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        resp.set_cookie(
            'BenchmarkTest00025',
            token,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict'
        )
        return resp

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_post():
        cookie_token = request.cookies.get('BenchmarkTest00025')
        session_token = session.get('BenchmarkTest00025_token')
        csrf_token = request.headers.get('X-CSRFToken')
        if not (cookie_token and session_token and csrf_token and cookie_token == session_token and csrf_token == session_token):
            abort(403)
        return "Welcome back: Nancy"