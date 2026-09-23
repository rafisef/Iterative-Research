from flask import request, make_response, render_template, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, BadTimeSignature
from datetime import datetime, timedelta

def init(app):
    salt = app.config.get('SECURITY_SALT', 'default-salt')
    serializer = URLSafeTimedSerializer(app.secret_key, salt=salt)
    require_ssl = app.config.get('SECURITY_REQUIRE_SSL', False)

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def _benchmark_get():
        if require_ssl and not request.is_secure:
            return jsonify(error='SSL required'), 400
        payload = {'shared': 'no pickles to be seen here'}
        token = serializer.dumps(payload)
        csrf_token = serializer.dumps({'csrf': True})
        resp = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        resp.set_cookie(
            'BenchmarkTest00078',
            token,
            max_age=180,
            expires=datetime.utcnow() + timedelta(seconds=180),
            secure=request.is_secure,
            httponly=True,
            samesite='Strict',
            path='/benchmark/deserialization-00/BenchmarkTest00078'
        )
        resp.set_cookie(
            'BenchmarkTest00078_csrf',
            csrf_token,
            max_age=180,
            expires=datetime.utcnow() + timedelta(seconds=180),
            secure=request.is_secure,
            httponly=False,
            samesite='Strict',
            path='/benchmark/deserialization-00/BenchmarkTest00078'
        )
        return resp

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def _benchmark_post():
        if require_ssl and not request.is_secure:
            return jsonify(error='SSL required'), 400
        token = request.cookies.get('BenchmarkTest00078')
        csrf_cookie = request.cookies.get('BenchmarkTest00078_csrf')
        header_csrf = request.headers.get('X-CSRF-Token')
        if not token or not csrf_cookie or not header_csrf or csrf_cookie != header_csrf:
            return jsonify(error='CSRF token missing or invalid'), 400
        try:
            data = serializer.loads(token, max_age=180)
        except (BadSignature, BadTimeSignature):
            return jsonify(error='Invalid or expired cookie'), 400
        except Exception:
            return jsonify(error='Internal error'), 500
        try:
            serializer.loads(csrf_cookie, max_age=180)
        except (BadSignature, BadTimeSignature):
            return jsonify(error='Invalid or expired CSRF token'), 400
        shared = data.get('shared', 'unknown')
        return jsonify(shared=shared)