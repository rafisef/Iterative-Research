from flask import Flask, redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite

def init(app: Flask):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
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

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        bar = param if 'should' in "This should never happen" else "This should never happen"

        sql = 'SELECT username FROM USERS WHERE password = ?'
        try:
            con = helpers.db_sqlite.get_connection()
            with con:
                cur = con.cursor()
                cur.execute(sql, (bar,))
                response = helpers.db_sqlite.results(cur, sql)
            return response
        except helpers.db_sqlite.DatabaseError:
            abort(500, description="Database error")
        finally:
            if con:
                con.close()