from flask import (
    Flask, redirect, url_for, request, make_response,
    render_template, session, current_app
)
from werkzeug.utils import escape
import secrets
import urllib.parse

def init(app: Flask) -> None:
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_get():
        token = secrets.token_urlsafe(32)
        resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        resp.set_cookie(
            'BenchmarkTest00025',
            token,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain='localhost'
        )
        session['BenchmarkTest00025_token'] = token
        return resp

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_post():
        cookie_token = request.cookies.get('BenchmarkTest00025')
        session_token = session.get('BenchmarkTest00025_token')
        response = ""
        if cookie_token and cookie_token == session_token:
            response += f"Welcome back: {escape('Nancy')}"
        else:
            new_token = secrets.token_urlsafe(32)
            session['BenchmarkTest00025_token'] = new_token
            response += (
                f"{escape('Nancy')} has been remembered with cookie: "
                f"{escape('BenchmarkTest00025')} whose value is: "
                f"{escape(new_token)}"
            )
        return response