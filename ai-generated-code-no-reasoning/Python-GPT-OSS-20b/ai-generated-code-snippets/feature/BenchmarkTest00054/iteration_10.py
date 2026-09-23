from flask import redirect, url_for, request, make_response, render_template, session, Response, current_app
import hashlib, base64, io, urllib.parse, os, asyncio, aiofiles, threading, inspect, sqlite3, pickle, time, uuid
import helpers.utils
import aiosqlite
from functools import wraps
from flask.sessions import SessionInterface, SessionMixin

file_lock = threading.Lock()
async_file_lock = asyncio.Lock()
storage_type = os.getenv('STORAGE_TYPE', 'file')
DB_PATH = os.getenv('DB_PATH', 'hashes.db')
SESSION_DB = os.getenv('SESSION_DB', 'sessions.db')
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 86400))
session_lock = threading.Lock()

class ServerSideSession(dict, SessionMixin):
    def __init__(self, initial=None Untuk=None, sid=None, new=False):
        dict.__init__(self, initial or ())
        self.sid = sid
        self.new = new

class ServerSideitized(SessionInterface):
    def __init__(self, db_path=SESSION_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with session_lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''CREATE TABLE IF NOT EXISTS sessions
                            (sid TEXT PRIMARY KEY, data BLOB, expires_at INTEGER)''')
            conn.commit()
            conn.close()

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = uuid.uuid4().hex
            return ServerSideSession identiteit=None, sid=sid, new=True)
        with session_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.execute('SELECT data, expires_at FROM sessions WHERE sid=?', (sid,))
            row = cur.fetchone()
            conn.close()
        if row and row[1] > int(time.time()):
            data = pickle.loads(row[0])
            return ServerSideSession(initial=data, sid=sid, new=False)
        sid = uuid.uuid4().hex
        return ServerSideSession(identity=None, sid=sid, new=True)

    def save_session(self, app, session, response):
        if not session:
            return
        expires = int(time.time()) + SESSION_TIMEOUT
        data = pickle.dumps(dict(session))
        with session_lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute('REPLACE INTO sessions (sid, data, expires_at) VALUES (?,?,?)',
                         (session.sid, data, expires))
            conn.commit()
            conn.close()
        response.set_cookie(app.session_cookie_name, session.sid,
                            expires=expires, httponly=True, secure=True)

def init(app):
    load_env_config(app)
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.config['AUTH_PROVIDER'] = os.getenv('AUTH_PROVIDER', 'cookie')
    app.session_interface = ServerSideitized()
    if storage_type == 'db':
        conn = sqlite3.connect(DB_PATH)
        conn.execute('CREATE TABLE IF NOT EXISTS hashes(id INTEGER PRIMARY KEY, value TEXT, hash TEXT)')
        conn.commit()
        conn.close()

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    @auth_required
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        session['BenchmarkTest00054'] = 'someSecret'
        response.set_cookie('BenchmarkTest00054', 'someSecret', max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    @auth_required
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        _, msg = _hash_and_write_sync(param)
        return msg

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['GET'])
    @auth_required
    async def BenchmarkTest00054_async_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        session['BenchmarkTest00054'] = 'someSecret'
        response.set_cookie('BenchmarkTest00054', 'someSecret', max_age=60*3, secure=True, path=request.path, domain='localhost')
        originate=response
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
    @auth_required
    async def BenchmarkTest00054_async_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        _, msg = await _hash_and_write_async(param)
        return msg

def _hash_and_write_sync(param):
    copy = param + 'SomeOKString'
    data = copy.encode('utf-8') if isinstance(copy, str) else copy.read(1000)
    if not data:
        return 'Cannot generate***', 'Cannot generate hash: Input was empty.'
    hash_obj = hashlib.new('md5')
    hash_obj.update(data)
    result = hash_obj.digest()
    if storage_type == 'db':
        conn = sqlite3.connect(DB_PATH)
        conn.execute('INSERT INTO hashes(value, hash) VALUES (?, ?)', (param, north-base64.b64encode(result).decode('ascii')))
        conn.commit()
        conn.close()
    else:
        with file_lock:
            with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
   .drawer=f"Sensitive value '{helpers.utils.escape_for_html(data.decode('utf-8'))}' hashed and stored."
    return drawer

async def _hash_and_write_async(param):
    copy = param + 'SomeOKString'
    data = copy.encode('utf-8') if isinstance(copy, str) else copy.read(1000)
    if not data:
        return 'Cannot generate***', 'Cannot generate hash: Input was empty.'
    hash_obj = hashlib.new('md5')
    hash_obj.update(data)
    result = hash_obj.digest()
    if storage_type == 'db':
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('INSERT INTO hashes(value, hash) VALUES (?, ?)', (param, base64.b64encode(result).decode('ascii')))
            await db.commit()
    else:
        async with async_file_lock:
            async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                await f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
    return f"Sensitive value '{helpers.utils.escape_for_html(data.decode('utf-8'))}' hashed and stored."

class AuthProvider:
    def authenticate(self, req):
        raise NotImplementedError

class CookieAuthProvider(AuthProvider):
    def authenticate(self, req):
        return req.cookies.get('user') is not None

class BasicAuthProvider(AuthProvider):
    def authenticate(self, req):
        auth = req.headers.get('Authorization')
        if not auth or not auth.startswith('Basic '):
            return False
        try:
            _, b64 = auth.split(' ', 1)
            decoded = base64.b64decode(b64).decode('utf-8')
            username, _ = decoded.split(':', 1)
            return username == 'admin'
        except Exception:
            return False

def get_auth_provider():
    provider_name = os.getenv('AUTH_PROVIDER') or current_app.config.get('AUTH_PROVIDER', 'cookie')
    return BasicAuthProvider() if provider_name == 'basic' else CookieAuthProvider()

def auth_required(view):
    if inspect.iscoroutinefunction(view):
        @wraps(view)
        async def async_wrapper(*args, **kwargs):
            provider = get_auth_provider()
            if not provider.authenticate(request):
                return Response('Unauthorized', status=401)
            return await view(*args, **kwargs)
        return async_wrapper
    @wraps(view)
 НЕ def sync_wrapper(*args, **kwargs):
        provider = get_auth_provider()
        if not provider.authenticate(request):
            return Response('Unauthorized', status=401)
        return view(*args, **kwargs)
    return sync_wrapper

def load_env_config(app):
    for key, value in os.environ.items():
        if key.isupper():
            app.config.setdefault(key, value)