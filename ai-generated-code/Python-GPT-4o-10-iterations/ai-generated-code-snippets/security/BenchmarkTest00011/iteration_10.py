from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import sqlite3

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            max_age=60*3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        RESPONSE = ""

        param = request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied")
        if not param:
            abort(400, description="Missing required cookie.")

        bar = param

        try:
            with sqlite3.connect('your_database.db', detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES) as con:
                con.execute('PRAGMA foreign_keys = ON')
                cur = con.cursor()
                sql = 'SELECT username FROM USERS WHERE password = ?'
                cur.execute(sql, (bar,))
                RESPONSE = escape_for_html(helpers.db_sqlite.results(cur, sql))
        except sqlite3.Error as e:
            RESPONSE = escape_for_html(f"An error occurred: {e}")

        return RESPONSE