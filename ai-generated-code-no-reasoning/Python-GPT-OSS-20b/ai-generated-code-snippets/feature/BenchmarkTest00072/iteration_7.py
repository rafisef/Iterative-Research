from flask import redirect, url_for, request, make_response, render_template, session
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from helpers.utils import escape_for_html
import urllib.parse
import uuid
import threading
import os
from collections import defaultdict

db = SQLAlchemy()
session_locks = defaultdict(threading.Lock)

def init(app, storage_type='file'):
    app.secret_key = 'super-secret-key'
    app.config['SESSION_COOKIE_NAME'] = 'BenchmarkTest00072_session'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE'] = True
    if storage_type == 'file':
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = '/tmp/flask_session'
        app.config['SESSION_PERMANENT'] = False
        os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)
    elif storage_type == 'db':
        app.config['SESSION_TYPE'] = 'sqlalchemy'
        app.config['SESSION_SQLALCHEMY_TABLE'] = 'sessions'
        app.config['SESSION_SQLALCHEMY'] = db
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sessions.db'
        app.config['SESSION_PERMANENT'] = False
        db.init_app(app)
        with app.app_context():
            db.create_all()
    Session(app)

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
    def BenchmarkTest00072_get():
        user_id = str(uuid.uuid4())
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie('BenchmarkTest00072', user_id,
                            max_age=60 * 3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        session['user_id'] = user_id
        session.modified = True
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
    def BenchmarkTest00072_post():
        user_id = request.cookies.get('BenchmarkTest00072')
        lock = session_locks[user_id]
        with lock:
            param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))
            TestParam = "This should never happen"
            if 'should' not in TestParam:
                bar = "Ifnot case passed"
            else:
                bar = param
            session[bar] = '12345'
            session.modified = True
            RESPONSE = f"Item: '{escape_for_html(bar)}' with value: 12345 saved in session."
            return RESPONSE

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072/session', methods=['GET'])
    def BenchmarkTest00072_session():
        user_id = request.cookies.get('BenchmarkTest00072')
        lock = session_locks[user_id]
        with lock:
            return str(dict(session))

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072/session/clear', methods=['POST'])
    def BenchmarkTest00072_clear_session():
        user_id = request.cookies.get('BenchmarkTest00072')
        lock = session_locks[user_id]
        with lock:
            session.clear()
            session.modified = True
            return 'Session cleared.'