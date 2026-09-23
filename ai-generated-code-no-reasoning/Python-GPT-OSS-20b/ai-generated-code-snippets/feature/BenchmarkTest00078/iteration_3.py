from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
import urllib.parse
import pickle
import base64

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
    def wrapper(*args, **kwargs):
        provider = request.cookies.get('auth_provider', 'basic')
        auth_func = providers.get(provider)
        if not auth_func:
            return make_response('Unsupported provider', 400)
        if not auth_func():
            return make_response('Unauthorized', 401)
        return f(*args, **kwargs)
    return wrapper

def init(app):
    app.secret_key = 'supersecretkey'
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    @require_auth
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie('BenchmarkTest00078',
                            'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waXNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
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