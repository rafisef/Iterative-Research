from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
    def BenchmarkTest00072():
        if request.method == 'GET':
            response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
            response.set_cookie('BenchmarkTest00072', 'my-user-id', max_age=180, secure=True, path='/benchmark/trustbound-00/BenchmarkTest00072', domain='localhost')
            return response
        param = request.cookies.get('BenchmarkTest00072', 'noCookieValueSupplied')
        bar = 'Ifnot case passed'
        session[bar] = '12345'
        return f"Item: '{escape_for_html(bar)}' with value: 12345 saved in session."