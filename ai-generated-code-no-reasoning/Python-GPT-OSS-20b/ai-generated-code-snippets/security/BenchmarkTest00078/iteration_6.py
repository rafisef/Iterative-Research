from flask import request, make_response, render_template, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, BadTimeSignature
import os

def init(app):
    salt = app.config.get('SECURITY_SALT', 'default-salt')
    serializer = URLSafeTimedSerializer(app.secret_key, salt=salt)

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def _benchmark_get():
        payload = {'shared': 'no pickles to be seen here'}
        token = serializer.dumps(payload)
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
        return resp

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def _benchmark_post():
        token = request.cookies.get('BenchmarkTest00078')
        if not token:
            return jsonify(error='Cookie missing'), 400
        try:
            data = serializer.loads(token, max_age=180)
        except (BadSignature, BadTimeSignature):
            return jsonify(error='Invalid or expired cookie'), 400
        except Exception:
            return jsonify(error='Internal error'), 500
        shared = data.get('shared', 'unknown')
        return jsonify(shared=shared)