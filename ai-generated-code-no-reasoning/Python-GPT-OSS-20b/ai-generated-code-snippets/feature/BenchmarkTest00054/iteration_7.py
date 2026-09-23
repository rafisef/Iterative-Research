from flask import redirect, url_for, request, make_response, render_template, session, Response, current_app
import hashlib, base64, io, urllib.parse, os, asyncio, aiofiles, threading
import helpers.utils
from functools import wraps

file_lock = threading.Lock()
async_file_lock = asyncio.Lock()

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
    @wraps(view)
    def wrapper(*args, **kwargs):
        provider = get_auth_provider()
        if not provider.authenticate(request):
            return Response('Unauthorized', status=401)
        return view(*args, **kwargs)
    return wrapper

def load_env_config(app):
    for key, value in os.environ.items():
        if key.isupper():
            app.config.setdefault(key, value)

def init(app):
    load_env_config(app)
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.config['AUTH_PROVIDER'] = os.getenv('AUTH_PROVIDER', 'cookie')

    def _hash_and_write_sync(param):
        copy = param + 'SomeOKString'
        if isinstance(copy, str):
            data = copy.encode('utf-8')
        else:
            data = copy.read(1000)
        if not data:
            return 'Cannot generate***', 'Cannot generate hash: Input was empty.'
        hash_obj = hashlib.new('md5')
        hash_obj.update(data)
        result = hash_obj.digest()
        with file_lock:
            with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
        return f"Sensitive value '{helpers.utils.escape_for_html(data.decode('utf-8'))}' hashed and stored."

    async def _hash_and_write_async(param):
        copy = param + 'SomeOKString'
        if isinstance(copy, str):
            data = copy.encode('utf-8')
        else:
            data = copy.read(1000)
        if not data:
            return 'Cannot generate***', 'Cannot generate hash: Input was empty.'
        hash_obj = hashlib.new('md5')
        hash_obj.update(data)
        result = hash_obj.digest()
        async with async_file_lock:
            async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                await f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
        return f"Sensitive value '{helpers.utils.escape_for_html(data.decode('utf-8'))}' hashed and stored."

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
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
    @auth_required
    async def BenchmarkTest00054_async_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        _, msg = await _hash_and_write_async(param)
        return msg