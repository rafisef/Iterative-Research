from flask import make_response, render_template, request
from helpers.utils import escape_for_html
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
            httponly=True,
            samesite='Strict',
            path='/'
        )
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        param = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
        sql = 'SELECT username FROM USERS WHERE password = ?'
        try:
            con = helpers.db_sqlite.get_connection()
            cur = con.cursor()
            cur.execute(sql, (param,))
            rows = cur.fetchall()
        finally:
            con.close()
        usernames = [escape_for_html(row[0]) for row in rows]
        return ', '.join(usernames)