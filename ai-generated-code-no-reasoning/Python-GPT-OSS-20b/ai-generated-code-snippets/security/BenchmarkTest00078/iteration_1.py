from flask import request, make_response, render_template, jsonify
import base64
import json

def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        payload = {'shared': 'no pickles to be seen here'}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            encoded,
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        cookie = request.cookies.get('BenchmarkTest00078')
        if not cookie:
            return jsonify(error='Cookie missing'), 400
        try:
            decoded = base64.urlsafe_b64decode(cookie.encode())
            data = json.loads(decoded.decode())
        except (ValueError, json.JSONDecodeError):
            return jsonify(error='Invalid cookie data'), 400
        shared = data.get('shared', 'unknown')
        return jsonify(shared=shared)