from flask import Flask, redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
import urllib.parse
import pickle
import base64
import os
from flask_session import Session
from sqlalchemy import create_engine, Table, Column, String, MetaData
from sqlalchemy.orm import scoped_session, sessionmaker
import inspect
from datetime import timedelta

providers = {}

def _basic_auth():
    auth = request.authorization
    return auth and auth.username == 'user' and auth.password == 'pass'

def _token_auth():
    token = request.headers.get('X-Auth-Token')
    return token == 'secrettoken'

providers['basic'] = _basic_auth
providers['token'] = _token_auth

def register_provider(name, func):
    providers[name] = func

def require_auth(f):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        provider = request.cookies.get('auth_provider', 'basic')
        auth_func = providers.get(provider)
        if not auth_func:
            return make_response('Unsupported provider', 400)
        if inspect.iscoroutinefunction(auth_func):
            auth_ok = await auth_func()
        else:
            auth_ok = auth_func()
        if not auth_ok:
            return make_response('Unauthorized', 401)
        if inspect.iscoroutinefunction(f):
            return await f(*args, **kwargs)
        return f(*args, **kwargs)
    return wrapper

def init(app, storage_type='sqlalchemy', db_uri='sqlite:///flask_session.db', file_dir='flask_session'):
    app.secret_key = 'supersecretkey'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    app.config['SESSION_COOKIE_NAME'] = 'user_session'
    if storage_type == 'filesystem':
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = file_dir
    elif storage_type == 'sqlalchemy':
        engine = create_engine(db_uri)
        metadata = MetaData()
        session_table = Table(
            'session',
            metadata,
            Column('id', String(255), primary_key=True),
            Column('data', String, nullable=False),
            Column('expiration', String, nullable=False)
        )
        metadata.create_all(engine)
        SessionLocal = scoped_session(sessionmaker(bind=engine))
        app.config['SESSION_SQLALCHEMY_TABLE'] = 'session'
        app.config['SESSION_SQLALCHEMY'] = engine
        app.config['SESSION_TYPE'] = 'sqlalchemy'
    else:
        raise ValueError('Unsupported storage type')
    Session(app)

    @app.route('/login/<provider>', methods=['GET'])
    async def login(provider):
        auth_func = providers.get(provider)
        if not auth_func:
            return make_response('Unsupported provider', 400)
        if inspect.iscoroutinefunction(auth_func):
            auth_ok = await auth_func()
        else:
            auth_ok = auth_func()
        if not auth_ok:
            return make_response('Unauthorized', 401)
        resp = make_response(redirect(url_for('session_info')))
        resp.set_cookie('auth_provider', provider, max_age=60 * 60 * 24, secure=True, path='/', httponly=True)
        return resp

    @app.route('/auth/providers')
    def list_providers():
        return {'providers': list(providers.keys())}

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    @require_auth
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie('BenchmarkTest00078',
                            'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b_1waXNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    @require_auth
    def BenchmarkTest00078_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00078", "noCookieValueSupplied"))
        string9895 = 'help' + param + 'snapes on a plane'
        bar = string9895[4:-17]
        try:
            unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
        except Exception:
            return 'Unpickling failed!'
        session['sharedstr'] = "no pickles to be seen here"
        return f'shared string is {session.get("sharedstr", "")}'

    @app.route('/session-info')
    @require_auth
    def session_info():
        return {
            'session_id': request.cookies.get(app.session_cookie_name),
            'data': dict(session)
        }

    @app.route('/logout')
    @require_auth
    def logout():
        session.clear()
        return redirect(url_for('BenchmarkTest00078_get'))