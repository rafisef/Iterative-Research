'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
import urllib.parse
import pickle
import base64

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        provider = request.cookies.get('auth_provider', 'basic')
        if provider == 'basic':
            auth = request.authorization
            if not auth or auth.username != 'user' or auth.password != 'pass':
                return make_response('Unauthorized', 401)
        elif provider == 'token':
            token = request.headers.get('X-Auth-Token')
            if token != 'secrettoken':
                return make_response('Unauthorized', 401)
        else:
            return make_response('Unsupported provider', 400)
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