from flask import request, make_response, render_template
import random
import urllib.parse
from helpers.utils import mysession

def init(app):
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
                            max_age=180,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00025', 'noCookieValueSupplied'))
        num = 'BenchmarkTest00025'[13:]  # '00025'
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]
        session = mysession
        if cookie in session and request.cookies.get(cookie) == session[cookie]:
            return f'Welcome back: {user}<br/>'
        session[cookie] = value
        return f'{user} has been remembered with cookie: {cookie} whose value is: {session[cookie]}<br/>'