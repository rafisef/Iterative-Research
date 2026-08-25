import urllib.parse

from flask import make_response, render_template, request
import helpers.db_sqlite


def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET', 'POST'])
    def benchmark_test_00011():
        if request.method == 'GET':
            response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
            response.set_cookie(
                'BenchmarkTest00011', 'bar',
                max_age=180,
                secure=True,
                httponly=True,
                samesite='Strict',
                path=request.path,
                domain='localhost'
            )
            return response

        cookie_val = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_val)
        bar = param if 'should' in param else 'This should never happen'

        sql = 'SELECT username FROM USERS WHERE password = ?'
        try:
            with helpers.db_sqlite.get_connection() as con:
                cur = con.cursor()
                cur.execute(sql, (bar,))
                result = helpers.db_sqlite.results(cur)
            return result
        except Exception:
            return make_response('Internal error', 500)