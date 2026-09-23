import os
import uuid
import json
import sqlite3
import asyncio
import aiofiles
import aiosqlite
from flask import Flask, request, make_response

def _bool_from_env(val, default=False):
    if val is None:
        return default
    return val.lower() in ('1', 'true', 'yes')

class FileSession(dict):
    def __init__(self, sid, initial=None):
        super().__init__(initial or {})
        self.sid = sid
    def get(self, key, default=None):
        return super().get(key, default)

class DBSession(dict):
    def __init__(self, sid, initial=None):
        super().__init__(initial or {})
        self.sid = sid
    def get(self, key, default=None):
        return super().get(key, default)

class FileSessionInterface:
    def __init__(self, folder=None):
        self.folder = folder or os.getenv('SESSION_FOLDER', 'session_data')
        os.makedirs(self.folder, exist_ok=True)
        self.cookie_http_only = _bool_from_env(os.getenv('SESSION_COOKIE_HTTPONLY'), True)
        self.cookie_secure = _bool_from_env(os.getenv('SESSION_COOKIE_SECURE'), True)
        self.cookie_path = os.getenv('SESSION_COOKIE_PATH', '/')
        self.cookie_max_age = int(os.getenv('SESSION_COOKIE_MAX_AGE', 86400))
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return FileSession(sid, {})
        path = os.path.join(self.folder, f'{sid}.json')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}
        return FileSession(sid, data)
    def save_session(self, app, session, response):
        path = os.path.join(self.folder, f'{session.sid}.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(session.data, f)
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=self.cookie_http_only,
                            secure=self.cookie_secure,
                            path=self.cookie_path,
                            max_age=self.cookie_max_age)
    async def open_session_async(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return FileSession(sid, {})
        path = os.path.join(self.folder, f'{sid}.json')
        if os.path.exists(path):
            async with aiofiles.open(path, 'r', encoding='utf-8') as f:
                content = await f.read()
                data = json.loads(content)
        else:
            data = {}
        return FileSession(sid, data)
    async def save_session_async(self, app, session, response):
        path = os.path.join(self.folder, f'{session.sid}.json')
        async with aiofiles.open(path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(session.data))
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=self.cookie_http_only,
                            secure=self.cookie_secure,
                            path=self.cookie_path,
                            max_age=self.cookie_max_age)

class DBSessionInterface:
    def __init__(self, db_path=None):
        self.db_path = db_path or os.getenv('SESSION_DB_PATH', 'sessions.sqlite')
        self.cookie_http_only = _bool_from_env(os.getenv('SESSION_COOKIE_HTTPONLY'), True)
        self.cookie_secure = _bool_from_env(os.getenv('SESSION_COOKIE_SECURE'), True)
        self.cookie_path = os.getenv('SESSION_COOKIE_PATH', '/')
        self.cookie_max_age = int(os.getenv('SESSION_COOKIE_MAX_AGE', 86400))
        conn = sqlite3.connect(self.db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT)')
        conn.commit()
        conn.close()
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return DBSession(sid, {})
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute('SELECT data FROM sessions WHERE id=?', (sid,))
        row = cur.fetchone()
        conn.close()
        if row:
            data = json.loads(row[0])
        else:
            data = {}
        return DBSession(sid, data)
    def save_session(self, app, session, response):
        conn = sqlite3.connect(self.db_path)
        conn.execute('REPLACE INTO sessions(id, data) VALUES(?,?)',
                     (session.sid, json.dumps(session.data)))
        conn.commit()
        conn.close()
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=self.cookie_http_only,
                            secure=self.cookie_secure,
                            path=self.cookie_path,
                            max_age=self.cookie_max_age)
    async def open_session_async(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return DBSession(sid, {})
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute('SELECT data FROM sessions WHERE id=?', (sid,)) as cursor:
                row = await cursor.fetchone()
        if row:
            data = json.loads(row[0])
        else:
            data = {}
        return DBSession(sid, data)
    async def save_session_async(self, app, session, response):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute('REPLACE INTO sessions(id, data) VALUES(?,?)',
                             (session.sid, json.dumps(session.data)))
            await db.commit()
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=self.cookie_http_only,
                            secure=self.cookie_secure,
                            path=self.cookie_path,
                            max_age=self.cookie_max_age)

def get_session_interface(storage=None, **kwargs):
    storage = storage or os.getenv('SESSION_STORAGE', 'file')
    if storage == 'file':
        return FileSessionInterface(**kwargs)
    elif storage == 'db':
        return DBSessionInterface(**kwargs)
    else:
        raise ValueError('Unsupported storage type')