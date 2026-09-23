from flask import make_response, render_template, request, session
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
    def BenchmarkTest00072():
        if request.method == 'GET':
            resp = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
            resp.set_cookie('BenchmarkTest00072', 'my-user-id', max_age=180, secure=True,
                            path='/benchmark/trustbound-00/BenchmarkTest00072', domain='localhost')
            return resp
        key = request.cookies.get('BenchmarkTest00072', 'noCookieValueSupplied')
        session['Ifnot case passed'] = '12345'
        return f"Item: '{escape_for_html('Ifnot case passed')}' with value: 12345 saved in session."