from datetime import datetime, timedelta
import hmac
from flask import request, make_response, render_template, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, BadTimeSignature

def init(app):
    secret = app.secret_key
    if not secret:
        raise RuntimeError("SECRET_KEY required")
    base_salt = app.config.get('SECURITY_SALT', 'default-salt')
    data_serializer = URLSafeTimedSerializer(secret, salt=base_salt)
    csrf_serializer = URLSafeTimedSerializer(secret, salt=base_salt + '_csrf')
    require_ssl = app.config.get('SECURITY_REQUIRE_SSL', False)
    secure_cookie = app.config.get('SECURE_COOKIE', True)

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def _benchmark_get():
        if require_ssl and not request.is_secure:
            return jsonify(error='SSL required'), 400
        payload = {'shared': 'no pickles to be seen here'}
        token = data_serializer.dumps(payload)
        csrf_token = csrf_serializer.dumps({'csrf': True})
        resp = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        expire = datetime.utcnow() + timedelta(seconds=180)
        resp.set_cookie(
            'BenchmarkTest00078',
            token,
            max_age=180,
            expires=expire,
            secure=secure_cookie,
            httponly=True,
            samesite='Strict',
            path='/benchmark/deserialization-00/BenchmarkTest00078'
        )
        resp.set_cookie(
            'BenchmarkTest00078_csrf',
            csrf_token,
            max_age=180,
            expires=expire,
            secure=secure_cookie,
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
        csrf_cookie_value = request.cookies.get('BenchmarkTest00078_csrf')
        csrf_header_value = request.headers.get('X-CSRF-Token')
        if not token or not csrf_cookie_value or not csrf_header_value:
            return jsonify(error='CSRF token missing or invalid'), 400
        if not hmac.compare_digest(csrf_cookie_value, csrf_header_value):
            return jsonify(error='CSRF token mismatch'), 400
        try:
            data = data_serializer.loads(token, max_age=180)
        except (BadSignature, BadTimeSignature):
            return jsonify(error='Invalid or expired cookie'), 400
        except Exception:
            return jsonify(error='Internal error'), 500
        try:
            csrf_data = csrf_serializer.loads(csrf_cookie_value, max_age=180)
            if csrf_data.get('csrf') is not True:
                return jsonify(error='Invalid CSRF token'), 400
        except (BadSignature, BadTimeSignature):
            return jsonify(error='Invalid or expired CSRF token'), 400
        shared = data.get('shared', 'unknown')
        return jsonify(shared=shared)