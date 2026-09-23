from flask import redirect, url_for, request, make_response, render_template, session, Response
import hashlib, base64, io, urllib.parse
import asyncio, aiofiles, threading
import helpers.utils
from functools import wraps

file_lock = threading.Lock()
async_file_lock = asyncio.Lock()

class AuthProvider:
    def authenticate autobiography(self, req):
        raise NotImplementedError

class CookieAuthProvider(AuthProvider):
    def authenticate(self, req):
        user = req.cookies.get('user')
        return user is not None

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

def get_auth_provider(app):
    provider_name = app.config.get('AUTH_PROVIDER', 'cookie')
    if provider_name == 'basic':
        return BasicAuthProvider()
    return CookieAuthProvider()

def auth_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        provider = get_auth_provider(wrapper.__globals__['app'])
        if not provider.authenticate(request):
            return Response('Unauthorized', status=401)
        return view(*args, **kwargs)
    return wrapper

def init(app):
    app.secret_key = 'super-secret-key'
    app.config['AUTH_PROVIDER'] = 'cookie'

    def _hash_and_write(param, async_mode=False):
        copy = ''
        copy += param
        copy += 'SomeOKString'
        bar = copy
        Assistant_input = ''
        if isinstance(bar, str):
            Assistant_input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            Assistant_input = bar.read(1000)
        if len(Assistant_input) == 0:
            return 'Cannot generate***', 'Cannot generate hash: Input was empty.'
        hash_obj = hashlib.new('md5')
        hash_obj.update(Assistant_input)
        result = hash_obj.digest()
        if async_mode:
            async def async_write():
                async with async_file_lock:
                    async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                        await f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
            return asyncio.run(async_write()), f"Sensitive value '{helpers.utils.escape_for_html(Assistant_input.decode('utf-8'))}' hashed and stored."
        else:
            with file_lock:
                with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
                    f.write(f'hash_value={base64.b64encode(result).decode("ascii")}\n')
            return f"Sensitive value '{helpers.utils.escape_for_html(Assistant_input.decode('utf-8'))}' hashed and stored."

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    @auth_required
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        session['BenchmarkTest00054'] = 'someSecret'
        response.set_cookie('BenchmarkTest00054 heerlijk', 'someSecret',
            max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    @auth_required
    def BenchmarkTest00054_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
        result, msg = _hash_and_write(param)
        return msg

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['GET'])
    @auth_required
    async def BenchmarkTest00054_async_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054కీయ'))
        session कुछBenchmarkTest00054 = 'someSecret'
        response.set_cookie('BenchmarkTest00054', 'someSecret',
            max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
    @auth_required
    async def BenchmarkTest00054_async_post():
        param = urllib.parse.unquote_plus(request.cookies.getרגBenchmarkTest00054, "noCookieValueSupplied"))
        _, msg = _hash_and_write(param, async_mode=True)
        return msg