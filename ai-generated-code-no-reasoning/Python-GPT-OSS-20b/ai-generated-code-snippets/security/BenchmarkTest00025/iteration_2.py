from flask import (
    Flask, redirect, url_for, request, make_response,
    render_template, session, abort
)
from werkzeug.utils import escape
import secrets

def init(app: Flask) -> None:
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_get():
        token = secrets.token_urlsafe(32)
        session['BenchmarkTest00025_token'] = token
        resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        resp.set_cookie(
            'BenchmarkTest00025',
            token,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Lax'
        )
        return resp

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_post():
        cookie_token = request.cookies.get('BenchmarkTest00025')
        session_token = session.get('BenchmarkTest00025_token')
        if not cookie_token or not session_token or cookie_token != session_token:
            abort(400)
        return f"Welcome back: {escape('Nancy')}"