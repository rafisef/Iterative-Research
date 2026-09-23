from flask import Flask, request, make_response, session, render_template_string, escape
import os
import secrets
import re
from datetime import timedelta
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_NAME='app_session',
    SESSION_COOKIE_PATH='/',
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_SECRET_KEY=os.getenv('CSRF_SECRET_KEY', secrets.token_hex(32)),
    WTF_CSRF_TIME_LIMIT=3600,
    WTF_CSRF_METHODS=['POST'],
    WTF_CSRF_CHECK_DEFAULT=True
)
csrf = CSRFProtect(app)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
    )
    response.headers['X-Download-Options'] = 'noopen'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['X-DNS-Prefetch-Control'] = 'off'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/app/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        resp = make_response(render_template_string('''
            <form method="post">
                {{ csrf_token() }}
                <input type="text" name="BenchmarkTest00072" maxlength="50" />
                <input type="submit" value="Submit" />
            </form>
        '''))
        resp.set_cookie(
            'BenchmarkTest00072',
            '12345',
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600,
            path='/app/BenchmarkTest00072'
        )
        return resp

    param = request.form.get('BenchmarkTest00072', '')
    param = re.sub(r'[^a-zA-Z0-9]', '', param)[:50]
    session['benchmark_test_00072'] = param
    cookie_value = request.cookies.get('BenchmarkTest00072', '')
    bar = escape(cookie_value)
    return render_template_string('<h1>{{ bar }}</h1>', bar=bar)

if __name__ == "__main__":
    app.run(ssl_context='adhoc')