from flask import make_response, render_template, request
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite

def init(app):
    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie(
            'BenchmarkTest00011',
            'bar',
            max_age=180,
            secure=request.is_secure,
            path=request.path,
            httponly=True,
            samesite='Lax'
        )
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied'))
        bar = "This should never happen"
        if 'should' in bar:
            bar = param
        sql = 'SELECT username from USERS where password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (bar,))
        results = helpers.db_sqlite.results(cur, sql)
        con.close()
        return escape_for_html(results)