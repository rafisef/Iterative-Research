import os
import json
import urllib.parse
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import helpers.db_sqlite

STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'db')
FILE_PATH = os.getenv('FILE_PATH', 'users.json')

def get_user_by_password(password):
    if STORAGE_TYPE == 'file':
        if not os.path.exists(FILE_PATH):
            return None
        with open(FILE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(password)
    else:
        sql = 'SELECT username FROM USERS WHERE password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (password,))
        row = cur.fetchone()
        con.close()
        return row[0] if row else None

def format_response(username):
    if username:
        return f'Username: {escape_for_html(username)}'
    return 'No user found'

def init(app):
    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        bar = "This should never happen"
        if 'should' in bar:
            bar = param
        username = get_user_by_password(bar)
        return format_response(username)