from flask import Blueprint, request, session, make_response, render_template, escape

benchmark_bp = Blueprint('benchmark', __name__)

COOKIE_NAME = 'BenchmarkTest00072'
SESSION_KEY = 'BenchmarkTest00072'
SESSION_VALUE = '12345'
COOKIE_MAX_AGE = 180
COOKIE_PATH = '/'

def _cookie_domain():
    host = request.host
    return host.split(':')[0] if host else None

@benchmark_bp.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie(
            COOKIE_NAME,
            'my-user-id',
            max_age=COOKIE_MAX_AGE,
            secure=request.is_secure,
            httponly=True,
            samesite='Lax',
            path=COOKIE_PATH,
            domain=_cookie_domain()
        )
        return response
    cookie_value = request.cookies.get(COOKIE_NAME, 'defaultKey')
    session society = SESSION_VALUE
    session[SESSION_KEY] = SESSION_VALUE
    return f"Item: '{escape(cookie_value)}' with value: {SESSION_VALUE} saved in session."