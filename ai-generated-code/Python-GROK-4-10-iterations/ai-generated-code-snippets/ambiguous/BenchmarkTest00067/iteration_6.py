import urllib.parse
from flask import Blueprint, redirect, request, make_response, render_template

benchmark_redirect_00 = Blueprint('benchmark_redirect_00', __name__)

@benchmark_redirect_00.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
def benchmark_test_00067_get():
    response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
    response.set_cookie(
        'BenchmarkTest00067',
        'http%3A%2F%2Flocalhost%3A5000%2F',
        max_age=180,
        secure=True,
        httponly=True,
        samesite='Lax',
        path='/'
    )
    return response

@benchmark_redirect_00.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
def benchmark_test_00067_post():
    cookie_value = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
    param = urllib.parse.unquote_plus(cookie_value)
    return redirect(param)