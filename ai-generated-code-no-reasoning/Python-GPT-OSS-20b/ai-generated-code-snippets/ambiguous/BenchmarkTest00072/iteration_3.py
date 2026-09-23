from flask import Blueprint, request, session, make_response, render_template, escape

benchmark_bp = Blueprint('benchmark', __name__)

@benchmark_bp.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie(
            'BenchmarkTest00072',
            'my-user-id',
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain=request.host.split(':')[0]
        )
        return response
    cookie_value = request.cookies.get('BenchmarkTest00072', 'defaultKey')
    session[cookie_value] = '12345'
    return f"Item: '{escape(cookie_value)}' with value: 12345 saved in session."