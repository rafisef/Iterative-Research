from flask import request, make_response, render_template
import random
from helpers.utils import mysession

COOKIE_NAME = 'BenchmarkTest00025'

def init(app):
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
    def benchmark_test_00025():
        if request.method == 'GET':
            resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
            resp.set_cookie(COOKIE_NAME, 'whatever', max_age=180, secure=True,
                            path=request.path, domain='localhost')
            return resp
        cookie = request.cookies.get(COOKIE_NAME, 'noCookieValueSupplied')
        if cookie == mysession.get(COOKIE_NAME):
            return 'Welcome back: Nancy00025<br/>'
        val = str(random.normalvariate())[2:]
        mysession[COOKIE_NAME] = val
        return f'Nancy00025 has been remembered with cookie: {COOKIE_NAME} whose value is: {val}<br/>'