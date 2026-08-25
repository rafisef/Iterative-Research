from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, mysession
from random import getrandbits

def init(app):

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
    def BenchmarkTest00025():
        if request.method == 'POST':
            RESPONSE = []
            param = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
            bar = param if len(param) > 10 else ""

            num = '25'
            user = f'Nancy{num}'
            cookie = f'rememberMe{num}'
            value = str(getrandbits(64))[2:]

            if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
                RESPONSE.append(f'Welcome back: {user}<br/>')
            else:
                mysession[cookie] = value
                RESPONSE.append(
                    f'{user} has been remembered with cookie: '
                    f'{cookie} whose value is: {mysession[cookie]}<br/>'
                )
            return ''.join(RESPONSE)
        
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever', max_age=180, secure=True, path=request.path, domain='localhost')
        return response