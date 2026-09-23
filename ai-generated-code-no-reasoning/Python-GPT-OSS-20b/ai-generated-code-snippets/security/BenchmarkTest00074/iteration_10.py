from flask import Flask, render_template, request, make_response
from markupsafe import escape
from itsdangerous import URLSafeTimedSerializer, BadSignature
import datetime

app = Flask(__name__)
app.secret_key = 'super-secret-key'

def init():
    serializer = URLSafeTimedSerializer(app.secret_key, salt='benchmark-cookie')
    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def get_handler():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.mimetype = 'text/html'
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def post_handler():
        cookie_val = request.cookies.get('BenchmarkTest00074', '')
        try:
            decoded = serializer.loads(cookie_val, max_age=180)
        except BadSignature:
            decoded = ''
        if len(decoded) > 1024:
            decoded = ''
        safe_output = escape(decoded)
        response = make_response(safe_output)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.mimetype = 'text/plain'
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074/cookie', methods=['GET'])
    def cookie_handler():
        raw = "%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27"
        signed_value = serializer.dumps(raw)
        expires = datetime.datetime.utcnow() + datetime.timedelta(seconds=180)
        response = make_response('')
        response.set_cookie('BenchmarkTest00074', signed_value, expires=expires,
                            max_age=180, path='/', secure=True, httponly=True, samesite='Strict')
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.mimetype = 'text/plain'
        return response

init()