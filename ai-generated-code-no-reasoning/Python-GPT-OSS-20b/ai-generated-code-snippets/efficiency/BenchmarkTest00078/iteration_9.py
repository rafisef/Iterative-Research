from flask import request, make_response, render_template

COOKIE_NAME = 'BenchmarkTest00078'
COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b_waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'

def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET', 'POST'])
    def benchmark():
        if request.method == 'GET':
            resp = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
            resp.set_cookie(COOKIE_NAME, COOKIE_VALUE, max_age=180, secure=True, path=request.path, domain='localhost')
            return resp
        if request.cookies.get(COOKIE_NAME) != COOKIE_VALUE:
            return 'Unpickling failed!'
        import helpers.utils as utils
        utils.sharedstr = "no pickles to be seen here"
        return f'shared string is {utils.sharedstr}'