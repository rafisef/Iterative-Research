import os
import threading
import asyncio
import sqlite3
from flask import Flask, redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

# Thread-safe dictionary for session management
session_lock = threading.Lock()
mysession = {}

app = Flask(__name__)

USE_DATABASE = os.getenv('USE_DATABASE', 'False').lower() in ('true', '1', 't')

def init_db():
    conn = sqlite3.connect('session.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            cookie TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_session_value(cookie):
    if USE_DATABASE:
        conn = sqlite3.connect('session.db')
        cursor = conn.cursor()
        cursor.execute('SELECT value FROM sessions WHERE cookie = ?', (cookie,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    else:
        return mysession.get(cookie)

def set_session_value(cookie, value):
    if USE_DATABASE:
        conn = sqlite3.connect('session.db')
        cursor = conn.cursor()
        cursor.execute('REPLACE INTO sessions (cookie, value) VALUES (?, ?)', (cookie, value))
        conn.commit()
        conn.close()
    else:
        mysession[cookie] = value

def init(app):
    if USE_DATABASE:
        init_db()

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        cookie_domain = os.getenv('COOKIE_DOMAIN', 'localhost')
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
            max_age=int(os.getenv('COOKIE_MAX_AGE', 60*3)),
            secure=bool(os.getenv('COOKIE_SECURE', True)),
            path=request.path,
            domain=cookie_domain)
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        return asyncio.run(handle_post_request())

    async def handle_post_request():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

        superstring = f'90583{param}abcd'
        bar = superstring[len('90583'):len(superstring)-5]

        import random

        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate(0, 1))[2:]

        async with session_lock:
            stored_value = get_session_value(cookie)
            if stored_value and request.cookies.get(cookie) == stored_value:
                RESPONSE += (
                    f'Welcome back: {user}<br/>'
                )
            else:
                set_session_value(cookie, value)
                RESPONSE += (
                    f'{user} has been remembered with cookie: '
                    f'{cookie} whose value is: {value}<br/>'
                )

        return RESPONSE

init(app)