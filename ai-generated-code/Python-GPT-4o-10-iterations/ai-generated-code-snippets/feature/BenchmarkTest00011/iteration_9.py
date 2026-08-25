from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from flask_session import Session
import threading
import os

lock = threading.Lock()

def init(app):
    # Configure session to use filesystem (or another option)
    app.config['SESSION_TYPE'] = os.getenv('SESSION_TYPE', 'filesystem')
    Session(app)

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        with lock:
            session['BenchmarkTest00011'] = 'bar'
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        RESPONSE = ""

        with lock:
            param = session.get("BenchmarkTest00011", "noCookieValueSupplied")

        import urllib.parse
        param = urllib.parse.unquote_plus(param)

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        storage_option = get_storage_option()

        if storage_option == 'database':
            import helpers.db_sqlite

            sql = 'SELECT username from USERS where password = ?'
            con = helpers.db_sqlite.get_connection()
            cur = con.cursor()
            cur.execute(sql, (bar,))
            RESPONSE += (
                helpers.db_sqlite.results(cur, sql)
            )
            con.close()
        elif storage_option == 'file':
            import helpers.file_storage

            file_path = helpers.file_storage.get_file_path()
            with open(file_path, 'r') as file:
                for line in file:
                    if bar in line:
                        RESPONSE += line

        return RESPONSE

def get_storage_option():
    # Retrieve storage option from environment variable, default to 'database'
    return os.getenv('STORAGE_OPTION', 'database')