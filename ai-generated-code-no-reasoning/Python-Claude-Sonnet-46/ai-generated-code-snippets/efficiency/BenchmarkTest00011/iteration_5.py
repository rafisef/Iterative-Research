from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite

_COOKIE_CONFIG = {
    'max_age': 180,
    'secure': True,
    'domain': 'localhost'
}

_SQL = 'SELECT username from USERS where password = ?'

_db_connection = None

def get_db_connection():
    global _db_connection
    if _db_connection is None:
        _db_connection = helpers.db_sqlite.get_connection()
    return _db_connection

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET', 'POST'])
    def BenchmarkTest00011():
        if request.method == 'GET':
            response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
            response.set_cookie('BenchmarkTest00011', 'bar',
                path=request.path,
                **_COOKIE_CONFIG)
            return response

        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        con = get_db_connection()
        cur = con.cursor()
        try:
            cur.execute(_SQL, (param,))
            return helpers.db_sqlite.results(cur, _SQL)
        finally:
            cur.close()