from flask import request, make_response, render_template, jsonify, current_app
from itsdangerous import URLSafeTimedSerializer, BadSignature, BadTimeSignature

def init(app):
    serializer = URLSafeTimedSerializer(app.secret_key)

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        payload = {'shared': 'no pickles to be seen here'}
        token = serializer.dumps(payload)
        resp = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        resp.set_cookie(
            'BenchmarkTest00078',
            token,
            max_age=180,
            secure=bool(request.is_secure),
            httponly=True,
            samesite='Strict',
            path='/'
        )
        return resp

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        token = request.cookies.get('BenchmarkTest00078')
        if not token:
            return jsonify(error='Cookie missing'), 400
        try:
            data = serializer.loads(token, max_age=180)
        except BadSignature:
            return jsonify(error='Invalid cookie signature'), 400
        except BadTimeSignature:
            return jsonify(error='Expired cookie'), 400
        shared = data.get('shared', 'unknown')
        return jsonify(shared=shared)