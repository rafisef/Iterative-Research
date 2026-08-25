from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import helpers.db_sqlite
import json
import os
import asyncio
import aiosqlite
import sqlite3
from concurrent.futures import ThreadPoolExecutor

class Storage:
    def save(self, data):
        raise NotImplementedError

    def retrieve(self, key):
        raise NotImplementedError

class AsyncStorage(Storage):
    async def save(self, data):
        raise NotImplementedError

    async def retrieve(self, key):
        raise NotImplementedError

class FileStorage(Storage):
    def __init__(self, file_path):
        self.file_path = file_path

    def save(self, data):
        self._write_to_file(data)

    def _write_to_file(self, data):
        with open(self.file_path, 'w') as f:
            json.dump(data, f)

    def retrieve(self, key):
        if not os.path.exists(self.file_path):
            return None
        data = self._read_from_file()
        return data.get(key, None)

    def _read_from_file(self):
        with open(self.file_path, 'r') as f:
            return json.load(f)

class AsyncFileStorage(AsyncStorage):
    def __init__(self, file_path):
        self.file_path = file_path

    async def save(self, data):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._write_to_file, data)

    def _write_to_file(self, data):
        with open(self.file_path, 'w') as f:
            json.dump(data, f)

    async def retrieve(self, key):
        if not os.path.exists(self.file_path):
            return None
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, self._read_from_file)
        return data.get(key, None)

    def _read_from_file(self):
        with open(self.file_path, 'r') as f:
            return json.load(f)

class DatabaseStorage(Storage):
    def save(self, data):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO storage (key, value) VALUES (?, ?)", (data['key'], data['value']))
        conn.commit()
        conn.close()

    def retrieve(self, key):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM storage WHERE key = ?", (key,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None

class AsyncDatabaseStorage(AsyncStorage):
    async def save(self, data):
        async with aiosqlite.connect('database.db') as db:
            await db.execute("INSERT INTO storage (key, value) VALUES (?, ?)", (data['key'], data['value']))
            await db.commit()

    async def retrieve(self, key):
        async with aiosqlite.connect('database.db') as db:
            async with db.execute("SELECT value FROM storage WHERE key = ?", (key,)) as cursor:
                result = await cursor.fetchone()
                return result[0] if result else None

def init(app, storage_option='file', storage_path='storage.json', async_mode=False):
    if storage_option == 'file':
        storage = AsyncFileStorage(storage_path) if async_mode else FileStorage(storage_path)
    elif storage_option == 'database':
        storage = AsyncDatabaseStorage() if async_mode else DatabaseStorage()
    else:
        raise ValueError("Invalid storage option")

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    async def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    async def BenchmarkTest00011_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        sql = f'SELECT username from USERS where password = ?'
        
        if isinstance(storage, AsyncStorage):
            async with aiosqlite.connect('database.db') as db:
                async with db.execute(sql, (bar,)) as cursor:
                    RESPONSE += await helpers.db_sqlite.async_results(cursor, sql)
        else:
            def run_sync_query():
                with sqlite3.connect('database.db') as db:
                    cursor = db.cursor()
                    cursor.execute(sql, (bar,))
                    results = cursor.fetchall()
                    return "\n".join([escape_for_html(row[0]) for row in results])

            loop = asyncio.get_event_loop()
            RESPONSE += await loop.run_in_executor(None, run_sync_query)

        return RESPONSE