from flask import request, make_response, render_template
import helpers.db_sqlite

_query = 'SELECT username FROM USERS WHERE password = ?'

def get_db():
    conn = helpers.db_sqlite.get_connection()
    conn.row_factory = lambda cursor, row: dict(row)
    return conn

def init(app):
    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET', 'POST'])
    def BenchmarkTest00011():
        if request.method == 'GET':
            return make_response(render_template('web/sqli-00/BenchmarkTest00011.html')).set_cookie(
                'BenchmarkTest00011', 'bar', max_age=180, secure=True, path=request.path, domain='localhost')
        param = request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied")
        with get_db() as conn:
            row = conn.execute(_query, (param,)).fetchone()
        return {'results': [row] if row else []}