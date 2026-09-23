from flask import redirect, request, make_response, render_template, url_for
from itsdangerous import URLSafeSerializer, BadSignature
from urllib.parse import urlparse

def init(app):
    serializer = URLSafeSerializer(app.secret_key, salt='redirect')
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        target = url_for('index', _external=True)
        signed = serializer.dumps(target)
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            'BenchmarkTest00067',
            signed,
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite='Lax',
            path='/'
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        cookie_value = request.cookies.get('BenchmarkTest00067')
        if not cookie_value:
            return redirect(url_for('index'))
        try:
            target = serializer.loads(cookie_value)
        except BadSignature:
            return redirect(url_for('index'))
        parsed = urlparse(target)
        host = request.host.split(':')[0]
        if parsed.scheme in ('http', 'https') and parsed.hostname == host:
            return redirect(target)
        if parsed.path and parsed.path.startswith('/'):
            return redirect(parsed.path)
        return redirect(url_for('index'))