from flask import Blueprint, request, session, make_response, render_template, escape, jsonify

benchmark_bp = Blueprint('benchmark', __name__)

COOKIE_NAME = 'BenchmarkTest00072'
SESSION_KEY = 'BenchmarkTest00072'
SESSION_VALUE = '12345'
COOKIE_MAX_AGE = 180
COOKIE_PATH = '/'

def _cookie_domain():
    host = request.host
    return host.split(':')[0] if host else None

def _set_secure_cookie(response, name, value):
    response.set_cookie(
        name,
        value,
        max_age=COOKIE_MAX_AGE,
        secure=request.is_secure,
        httponly=True,
        samesite='Lax',
        path=COOKIE_PATH,
        domain=_cookie_domain()
    )

@benchmark_bp.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        _set_secure_cookie(response, COOKIE_NAME, 'my-user-id')
        return response
    cookie_value = request.cookies.get(COOKIE_NAME, 'defaultKey')
    session[SESSION_KEY] = SESSION_VALUE
    return jsonify(item=escape(cookie_value), session_value=SESSION_VALUE)

@benchmark_bp.route('/benchmark/trustbound-00/BenchmarkTest00072/clear', methods=['POST'])
def clear_benchmark_test_00072():
    response = make_response(jsonify(status='cleared'))
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, domain=_cookie_domain())
    session.pop(SESSION_KEY, None)
    return response