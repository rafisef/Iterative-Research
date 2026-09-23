from flask import request, make_response, render_template, g
import helpers.db_sqlite
import sqlite3

def get_db():
    if 'db' not in g:
        g.db = helpers.db_sqlite.get_connection()
        g.db.row_factory = sqlite3.Row
    return g.db

def init(app):
    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET', 'POST'])
    def BenchmarkTest00011():
        if request.method == 'GET':
            return make_response(render_template('web/sqli-00/BenchmarkTest00011.html')).set_cookie(
                'BenchmarkTest00011', 'bar', max_age=180, secure=True, path=request.path, domain='localhost')
        param = request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied")
        return {'results': [dict(row) for row in get_db().execute('SELECT username FROM USERS WHERE password = ?', (param,))]}

    @app.teardown_appcontext
    def close_db(exception=None):
        db = g.pop('db', None)
        if db:
            db.close()