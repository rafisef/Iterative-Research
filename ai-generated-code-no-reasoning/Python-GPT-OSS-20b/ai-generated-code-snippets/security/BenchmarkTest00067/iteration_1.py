from flask import redirect, request, make_response, render_template
import urllib.parse
import base64

def init(app):
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            'BenchmarkTest00067',
            'http%3A%2F%2Flocalhost%3A5000%2F',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            path=request.path,
            domain=request.host.split(':')[0]
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        cookie_value = request.cookies.get('BenchmarkTest00067', '')
        if not cookie_value:
            return redirect(url_for('index'))
        decoded = urllib.parse.unquote_plus(cookie_value)
        try:
            decoded_bytes = base64.b64decode(decoded.encode('utf-8'))
            target = decoded_bytes.decode('utf-8')
        except Exception:
            return redirect(url_for('index'))
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme in ('http', 'https') and parsed.netloc.endswith(request.host.split(':')[0]):
            return redirect(target)
        if parsed.path:
            return redirect(parsed.path)
        return redirect(url_for('index'))