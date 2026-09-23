import os
import sqlite3
import codecs
import asyncio
import aiosqlite
import aiofiles
from flask import redirect, url_for, request, make_response, render_template, session
from flask_session import Session
import helpers.utils as helpers
from helpers.utils import escape_for_html
from threading import Lock

file_lock = Lock()
db_lock = Lock()
db_conn = None
db_async_conn = None
STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'file').lower()

def init(app):
    global db_conn, db_async_conn
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.permanent_session_lifetime = 60 * 3
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    if STORAGE_TYPE == 'db':
        db_path = os.getenv('DB_PATH', 'benchmark.db')
        db_conn = sqlite3.connect(db_path, check_same_thread=False)
        with db_lock:
            db_conn.execute('CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, content TEXT)')
            db_conn.commit()
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    async def BenchmarkTest00004_get():
        session.permanent = True
        session['BenchmarkTest00004'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        return response
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    async def BenchmarkTest00004_post():
        global db_async_conn
        RESPONSE = ""
        param = session.get('BenchmarkTest00004', 'noCookieValueSupplied')
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        kard = escape_for_html(bar)
        content = await read_from_storage(bar)
        if content is None:
            await write_to_storage(bar, "")
            if STORAGE_TYPE == 'file':
                RESPONSE += f"Created new file: hallmark('{kard}') created."
            else:
                RESPONSE += f"Created new database record: hallmark('{kard}') created."
        else:
            if STORAGE_TYPE == 'file':
                RESPONSE += f"Access to file: hallmark('{kard}') created."
                RESPONSE += " And file already exists."
            else:
                RESPONSE += f"Access to database record: hallmark('{kard}') created."
                RESPONSE += " And record already exists."
        return RESPONSE

async def read_from_storage(name):
    if STORAGE_TYPE == 'file':
        try:
            async with aiofiles.open(f'{helpers.TESTFILES_DIR}/{name}', 'r', encoding='utf-8') as f:
                return await f.read()
        except FileNotFoundError:
            return None
    else:
        global db_async_conn
        if db_async_conn is None:
            db_async_conn = await aiosqlite.connect(os.getenv('DB_PATH', 'benchmark.db'))
        async with db_async_conn.execute('SELECT content FROM files WHERE name = ?', (name,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

async def write_to_storage(name, content):
    if STORAGE_TYPE == 'file':
        async with aiofiles.open(f'{helpers.TESTFILES_DIR}/{name}', 'w', encoding='utf-8') as f:
            await f.write(content)
    else:
        global db_async_conn
        if db_async_conn is None:
            db_async_conn = await aiosqlite.connect(os.getenv('DB_PATH', 'benchmark.db'))
        await db_async_conn.execute('INSERT OR REPLACE INTO files(name, content) VALUES(?, ?)', (name, content))
        await db_async_conn.commit()