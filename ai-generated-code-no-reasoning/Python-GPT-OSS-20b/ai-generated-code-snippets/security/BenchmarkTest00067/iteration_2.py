from flask import redirect, request, make_response, render_template, url_for
import urllib.parse
import base64
import binascii
from itsdangerous import Signer, BadSignature

def init(app):
    signer = Signer(app.secret_key)
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        target = 'http://localhost:5000/'
        encoded = base64.b64encode(target.encode('utf-8')).decode('utf-8')
        signed = signer.sign(encoded.encode('utf-8')).decode('utf-8')
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            'BenchmarkTest00067',
            signed,
            max_age=180,
            secure=True,
            httponly=True,
            path=request.path,
            domain=request.host.split(':')[0]
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        cookie_value = request.cookies.get('BenchmarkTest00067')
        if not cookie_value:
            return redirect(url_for('index'))
        try:
            unsigned = signer.unsign(cookie_value.encode('utf-8')).decode('utf-8')
            decoded_bytes = base64.b64decode(unsigned.encode('utf-8'))
            target = decoded_bytes.decode('utf-8')
        except (BadSignature, binascii.Error, UnicodeDecodeError, ValueError):
            return redirect(url_for('index'))
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme in ('http', 'https') and parsed.netloc.endswith(request.host.split(':')[0]):
            return redirect(target)
        if parsed.path:
            return redirect(parsed.path)
        return redirect(url_for('index'))