from flask import request, make_response, render_template
from itsdangerous import URLSafeTimedSerializer, BadSignature
import datetime
from markupsafe import escape

def init(app):
    serializer = URLSafeTimedSerializer(app.secret_key, salt='benchmark-cookie')
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        raw = "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27"
        cookie_value = serializer.dumps(raw)
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=180)
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie(
            'BenchmarkTest00074',
            cookie_value,
            max_age=180,
            expires=expires,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/'
        )
        response.mimetype = 'text/html'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        cookie_val = request.cookies.get('BenchmarkTest00074', '')
        try:
            decoded = serializer.loads(cookie_val, max_age=180)
        except BadSignature:
            decoded = ''
        if len(decoded) > 1024:
            decoded = ''
        safe_output = escape(decoded)
        response = make_response(safe_output)
        response.mimetype = 'text/plain'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response