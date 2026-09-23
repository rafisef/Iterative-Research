from flask import redirect, url_for, request, make_response, render_template, session
from flask_session import Session
from helpers.utils import escape_for_html
from threading import Lock
import os
import sqlite3
import codecs

file_lock = Lock()
db_lock = Lock()
db_conn = None
STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'file').lower()

def init(app):
    global db_conn
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.permanent_session_lifetime = 60 * 3
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    if STORAGE_TYPE == 'db':
        db_path = os.getenv('DB_PATH', 'benchmark.db')
        db_conn = sqlite3.connect(db_path, check_same_thread=False)
        with db_lock:
            db_conn.execute('CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, content TEXT)')
            db_conn.commit()
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        session.permanent = True
        session['BenchmarkTest00004'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        return response
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        RESPONSE = ""
        param = session.get('BenchmarkTest00004', 'noCookieValueSupplied')
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        try:
            kard = escape_for_html(bar)
            if STORAGE_TYPE == 'file':
                with file_lock:
                    fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}', 'r', 'utf-8')
                    RESPONSE += f"Access to file: hallmark('{kard}') created."
                    RESPONSE += " And file already exists."
            else:
                with db_lock:
                    cur = db_conn.execute('SELECT content FROM files WHERE name = ?', (bar,))
                    row = cur.fetchone()
                    if row:
                        RESPONSE += f"Access to database record: hallmark('{kard}') created."
                        RESPONSE += " And record already exists."
                    else:
                        raise FileNotFoundError()
        except FileNotFoundError:
            RESPONSE += " But file doesn't exist yet."
        return RESPONSE