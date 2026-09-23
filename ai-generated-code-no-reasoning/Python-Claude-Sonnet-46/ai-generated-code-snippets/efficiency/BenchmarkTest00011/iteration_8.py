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
_COOKIE_NAME = 'BenchmarkTest00011'
_NO_COOKIE = 'noCookieValueSupplied'

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET', 'POST'])
    def BenchmarkTest00011():
        if request.method == 'GET':
            response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
            response.set_cookie(_COOKIE_NAME, 'bar',
                path=request.path,
                **_COOKIE_CONFIG)
            return response

        raw = request.cookies.get(_COOKIE_NAME)
        param = urllib.parse.unquote_plus(raw) if raw else _NO_COOKIE
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(_SQL, (param,))
        result = helpers.db_sqlite.results(cur, _SQL)
        cur.close()
        return result