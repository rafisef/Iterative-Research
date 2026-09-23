from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from helpers import db_sqlite

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def benchmark_test_00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie(
            'BenchmarkTest00011',
            'bar',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def benchmark_test_00011_post():
        param = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
        sql = 'SELECT username FROM USERS WHERE password = ?'
        con = db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (param,))
        result = db_sqlite.results(cur, sql)
        con.close()
        return result