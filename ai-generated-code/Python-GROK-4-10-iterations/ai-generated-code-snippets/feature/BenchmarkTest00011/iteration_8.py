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
import asyncio
import secrets
from threading import Lock

AUTH_PROVIDERS = {
    'local': lambda u, p: True,
    'oauth': lambda u, p: False,
    'ldap': lambda u, p: False,
}

SESSION_LOCK = Lock()
CONCURRENT_SESSIONS = {}

def authenticate(provider, username, password):
    if provider in AUTH_PROVIDERS:
        return AUTH_PROVIDERS[provider](username, password)
    return False

async def authenticate_async(provider, username, password):
    if provider in AUTH_PROVIDERS:
        result = AUTH_PROVIDERS[provider](username, password)
        if asyncio.iscoroutine(result):
            return await result
        return result
    return False

def init(app):
    app.secret_key = secrets.token_hex(32)

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
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        storage = request.args.get('storage', 'database')
        if storage == 'file':
            with open('/tmp/benchmark_store.txt', 'a') as f:
                f.write(bar + '\n')
            RESPONSE += 'Stored to file'
        else:
            import helpers.db_sqlite

            sql = f'SELECT username from USERS where password = ?'
            con = helpers.db_sqlite.get_connection()
            cur = con.cursor()
            cur.execute(sql, (bar,))
            RESPONSE += (
                helpers.db_sqlite.results(cur, sql)
            )
            con.close()

        return RESPONSE

    @app.route('/benchmark/sqli-00/BenchmarkTest00011_async', methods=['POST'])
    async def BenchmarkTest00011_post_async():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        storage = request.args.get('storage', 'database')
        if storage == 'file':
            with open('/tmp/benchmark_store.txt', 'a') as f:
                f.write(bar + '\n')
            RESPONSE += 'Stored to file'
        else:
            import helpers.db_sqlite

            sql = f'SELECT username from USERS where password = ?'
            con = helpers.db_sqlite.get_connection()
            cur = con.cursor()
            cur.execute(sql, (bar,))
            RESPONSE += (
                helpers.db_sqlite.results(cur, sql)
            )
            con.close()

        return RESPONSE

    @app.before_request
    def manage_concurrent_sessions():
        with SESSION_LOCK:
            sid = session.get('sid')
            if not sid:
                sid = secrets.token_hex(16)
                session['sid'] = sid
            CONCURRENT_SESSIONS[sid] = session