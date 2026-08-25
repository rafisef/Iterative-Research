from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import mysession
import random
import urllib.parse

def init(app):

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
    def BenchmarkTest00025():
        return BenchmarkTest00025_post() if request.method == 'POST' else BenchmarkTest00025_get()

    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    def BenchmarkTest00025_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))
        bar = f'90583{param}abcd'[5:-4]
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]

        if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
            return f'Welcome back: {user}<br/>'

        mysession[cookie] = value
        return f'{user} has been remembered with cookie: {cookie} whose value is: {mysession[cookie]}<br/>'