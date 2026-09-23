from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite
from functools import lru_cache

_COOKIE_CONFIG = {
    'max_age': 180,
    'secure': True,
    'domain': 'localhost'
}

_SQL = 'SELECT username from USERS where password = ?'

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            path=request.path,
            **_COOKIE_CONFIG)
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(_SQL, (param,))
        RESPONSE = helpers.db_sqlite.results(cur, _SQL)
        con.close()
        return RESPONSE