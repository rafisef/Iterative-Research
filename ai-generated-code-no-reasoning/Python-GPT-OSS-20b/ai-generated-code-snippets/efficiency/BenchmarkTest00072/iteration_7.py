from flask import make_response, render_template, request, session

def init(app):
    cookie_name = 'BenchmarkTest00072'
    key = 'Ifnot case passed'

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
    def BenchmarkTest00072():
        if request.method == 'GET':
            resp = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
            resp.set_cookie(cookie_name, 'my-user-id', max_age=180, secure=True,
                            path='/benchmark/trustbound-00/BenchmarkTest00072', domain='localhost')
            return resp
        session[key] = '12345'
        return f"Item: '{key}' with value: 12345 saved in session."