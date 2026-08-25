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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import sqlite3
import aiofiles
import asyncio
import aiosqlite

STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'file')  # Can be 'file' or 'database'
SESSION_FILE = os.getenv('SESSION_FILE', 'session_data.txt')
DATABASE_FILE = os.getenv('DATABASE_FILE', 'session_data.db')

if STORAGE_TYPE == 'database':
    conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (cookie TEXT PRIMARY KEY, value TEXT)''')
    conn.commit()

async def async_file_store(cookie, value):
    async with aiofiles.open(SESSION_FILE, 'a') as f:
        await f.write(f"{cookie}:{value}\n")

async def async_file_load(cookie):
    if not os.path.exists(SESSION_FILE):
        return None
    async with aiofiles.open(SESSION_FILE, 'r') as f:
        async for line in f:
            stored_cookie, stored_value = line.strip().split(':')
            if stored_cookie == cookie:
                return stored_value
    return None

async def async_db_store(cookie, value):
    async with aiosqlite.connect(DATABASE_FILE) as db:
        await db.execute('REPLACE INTO sessions (cookie, value) VALUES (?, ?)', (cookie, value))
        await db.commit()

async def async_db_load(cookie):
    async with aiosqlite.connect(DATABASE_FILE) as db:
        async with db.execute('SELECT value FROM sessions WHERE cookie = ?', (cookie,)) as cursor:
            result = await cursor.fetchone()
            return result[0] if result else None

def store_session(cookie, value, sync=True):
    if sync:
        if STORAGE_TYPE == 'file':
            file_store(cookie, value)
        elif STORAGE_TYPE == 'database':
            db_store(cookie, value)
    else:
        if STORAGE_TYPE == 'file':
            asyncio.run(async_file_store(cookie, value))
        elif STORAGE_TYPE == 'database':
            asyncio.run(async_db_store(cookie, value))

def load_session(cookie, sync=True):
    if sync:
        if STORAGE_TYPE == 'file':
            return file_load(cookie)
        elif STORAGE_TYPE == 'database':
            return db_load(cookie)
    else:
        if STORAGE_TYPE == 'file':
            return asyncio.run(async_file_load(cookie))
        elif STORAGE_TYPE == 'database':
            return asyncio.run(async_db_load(cookie))

def file_store(cookie, value):
    with open(SESSION_FILE, 'a') as f:
        f.write(f"{cookie}:{value}\n")

def file_load(cookie):
    if not os.path.exists(SESSION_FILE):
        return None
    with open(SESSION_FILE, 'r') as f:
        for line in f:
            stored_cookie, stored_value = line.strip().split(':')
            if stored_cookie == cookie:
                return stored_value
    return None

def db_store(cookie, value):
    cursor.execute('REPLACE INTO sessions (cookie, value) VALUES (?, ?)', (cookie, value))
    conn.commit()

def db_load(cookie):
    cursor.execute('SELECT value FROM sessions WHERE cookie = ?', (cookie,))
    result = cursor.fetchone()
    return result[0] if result else None

def init(app):
    
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response
        return BenchmarkTest00025_post()

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

        superstring = f'90583{param}abcd'
        bar = superstring[len('90583'):len(superstring)-5]

        import random
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]

        stored_value = load_session(cookie)

        if stored_value and request.cookies.get(cookie) == stored_value:
            RESPONSE += (
                f'Welcome back: {user}<br/>'
            )
        else:
            store_session(cookie, value)
            RESPONSE += (
                f'{user} has been remembered with cookie: '
                f'{cookie} whose value is: {value}<br/>'
            )

        return RESPONSE