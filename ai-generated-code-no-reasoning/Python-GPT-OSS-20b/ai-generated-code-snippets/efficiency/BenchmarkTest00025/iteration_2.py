from flask import request, make_response, render_template
import random
from helpers.utils import mysession

def init(app):
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
    def benchmark_test_00025():
        cookie_name = 'BenchmarkTest00025'
        if request.method == 'GET':
            resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
            resp.set_cookie(cookie_name, 'whatever', max_age=180, secure=True,
                            path=request.path, domain='localhost')
            return resp
        cookie_value = request.cookies.get(cookie_name, 'noCookieValueSupplied')
        session = mysession
        if cookie_name in session and cookie_value == session[cookie_name]:
            return f'Welcome back: Nancy00025<br/>'
        session[cookie_name] = str(random.normalvariate())[2:]
        return f'Nancy00025 has been remembered with cookie: {cookie_name} whose value is: {session[cookie_name]}<br/>'