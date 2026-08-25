from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            max_age=60*3,
            secure=True,
            httponly=True,
            path=request.path,
            domain='localhost',
            samesite='Strict')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        import helpers.db_sqlite

        sql = 'SELECT username FROM USERS WHERE password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        try:
            cur.execute(sql, (bar,))
            RESPONSE += (
                helpers.db_sqlite.results(cur, sql)
            )
        finally:
            cur.close()  # Ensure the cursor is closed
            con.close()  # Ensure the connection is closed in a finally block

        return RESPONSE