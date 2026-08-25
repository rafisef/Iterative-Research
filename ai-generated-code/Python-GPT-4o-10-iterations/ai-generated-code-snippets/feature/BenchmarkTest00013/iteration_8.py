import os
import asyncio
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import sqlite3
import json

class AuthProvider:
    async def authenticate(self, request):
        raise NotImplementedError

class CookieAuthProvider(AuthProvider):
    async def authenticate(self, request):
        return request.cookies.get(
            os.getenv("COOKIE_NAME", "BenchmarkTest00013"), 
            os.getenv("COOKIE_FALLBACK", "noCookieValueSupplied")
        )

class OAuthProvider(AuthProvider):
    async def authenticate(self, request):
        return request.headers.get(
            os.getenv("AUTH_HEADER_NAME", "Authorization"), 
            os.getenv("TOKEN_FALLBACK", "noTokenSupplied")
        )

class StorageProvider:
    async def store(self, key, value):
        raise NotImplementedError
    
    async def retrieve(self, key):
        raise NotImplementedError

class FileStorageProvider(StorageProvider):
    def __init__(self, file_path):
        self.file_path = file_path

    async def store(self, key, value):
        data = {}
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = json.load(f)
        data[key] = value
        with open(self.file_path, 'w') as f:
            json.dump(data, f)

    async def retrieve(self, key):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = json.load(f)
                return data.get(key)
        return None

class DatabaseStorageProvider(StorageProvider):
    def __init__(self, db_path):
        self.db_path = db_path
        self._initialize_db()

    def _initialize_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS storage (key TEXT PRIMARY KEY, value TEXT)''')
        conn.commit()
        conn.close()

    async def store(self, key, value):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

    async def retrieve(self, key):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT value FROM storage WHERE key = ?', (key,))
        result = c.fetchone()
        conn.close()
        if result:
            return result[0]
        return None

def init(app, auth_providers, storage_provider):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            os.getenv("COOKIE_NAME", "BenchmarkTest00013"), 
            os.getenv("COOKIE_VALUE", "2222"),
            max_age=int(os.getenv("COOKIE_MAX_AGE", 60*3)),
            secure=bool(int(os.getenv("COOKIE_SECURE", 1))),
            path=request.path,
            domain=os.getenv("COOKIE_DOMAIN", "localhost")
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    async def BenchmarkTest00013_post():
        RESPONSE = ""

        import urllib.parse

        param = "noAuthValueSupplied"
        for provider in auth_providers:
            param = await provider.authenticate(request)
            if param != "noAuthValueSupplied":
                break

        param = urllib.parse.unquote_plus(param)

        bar = "alsosafe"
        if param:
            lst = []
            lst.append('safe')
            lst.append(param)
            lst.append('moresafe')
            lst.pop(0)
            bar = lst[1]

        import elementpath
        import xml.etree.ElementTree as ET
        import helpers.utils

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([e.text for e in node]))

            RESPONSE += (
                f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
            )
        except:
            RESPONSE += (
                f'Error parsing XPath Query: \'{escape_for_html(query)}\''
            )

        await storage_provider.store('last_query', query)
        return RESPONSE