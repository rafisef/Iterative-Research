from flask import Flask, request, make_response, session, escape, render_template_string
import re
import os
import secrets
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET_KEY', secrets.token_hex(32))
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='session',
    SESSION_REFRESH_EACH_REQUEST=True
)

def generate_csrf_token():
    token = secrets.token_urlsafe(64)
    session['csrf_token'] = token
    return token

def validate_csrf_token(token):
    return token == session.get('csrf_token')

@app.route('/app/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        csrf_token = generate_csrf_token()
        resp = make_response(render_template_string(f"""
            <form method="post">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <input type="text" name="BenchmarkTest00072" />
                <input type="submit" value="Submit" />
            </form>
        """))
        resp.set_cookie('BenchmarkTest00072', '12345', httponly=True, secure=True, samesite='Lax')
        return resp
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        return 'CSRF validation failed', 400
    param = request.form.get('BenchmarkTest00072', '')
    param = re.sub(r'[^a-zA-Z0-9]', '', param)
    param = param[:50]
    cookie_value = request.cookies.get('BenchmarkTest00072', '')
    session[param] = '12345'
    bar = escape(cookie_value)
    return render_template_string("<h1>{{ bar }}</h1>", bar=bar)

if __name__ == "__main__":
    app.run(ssl_context='adhoc')