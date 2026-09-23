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
from abc import ABC, abstractmethod
import json
import os
from datetime import datetime

class StorageBackend(ABC):
    @abstractmethod
    def save_query_result(self, test_id, param, result):
        pass
    
    @abstractmethod
    def get_query_results(self, test_id):
        pass

class FileStorageBackend(StorageBackend):
    def __init__(self, base_path='./storage'):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
    
    def save_query_result(self, test_id, param, result):
        file_path = os.path.join(self.base_path, f'{test_id}.json')
        data = []
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                data = json.load(f)
        
        data.append({
            'timestamp': datetime.now().isoformat(),
            'param': param,
            'result': result
        })
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_query_results(self, test_id):
        file_path = os.path.join(self.base_path, f'{test_id}.json')
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        return []

class DatabaseStorageBackend(StorageBackend):
    def __init__(self, db_module, db_type='sqlite'):
        self.db_module = db_module
        self.db_type = db_type
        self._init_table()
    
    def _init_table(self):
        con = self.db_module.get_connection()
        cur = con.cursor()
        if self.db_type == 'sqlite':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_id TEXT NOT NULL,
                    param TEXT,
                    result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        elif self.db_type == 'mysql':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    test_id VARCHAR(255) NOT NULL,
                    param LONGTEXT,
                    result LONGTEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        elif self.db_type == 'postgresql':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id SERIAL PRIMARY KEY,
                    test_id VARCHAR(255) NOT NULL,
                    param TEXT,
                    result TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        con.commit()
        con.close()
    
    def save_query_result(self, test_id, param, result):
        con = self.db_module.get_connection()
        cur = con.cursor()
        if self.db_type == 'sqlite':
            cur.execute('''
                INSERT INTO benchmark_results (test_id, param, result)
                VALUES (?, ?, ?)
            ''', (test_id, param, result))
        elif self.db_type in ['mysql', 'postgresql']:
            cur.execute('''
                INSERT INTO benchmark_results (test_id, param, result)
                VALUES (%s, %s, %s)
            ''', (test_id, param, result))
        con.commit()
        con.close()
    
    def get_query_results(self, test_id):
        con = self.db_module.get_connection()
        cur = con.cursor()
        cur.execute('''
            SELECT test_id, param, result, timestamp
            FROM benchmark_results
            WHERE test_id = ?
            ORDER BY timestamp DESC
        ''' if self.db_type == 'sqlite' else '''
            SELECT test_id, param, result, timestamp
            FROM benchmark_results
            WHERE test_id = %s
            ORDER BY timestamp DESC
        ''', (test_id,))
        results = cur.fetchall()
        con.close()
        
        return [
            {
                'test_id': r[0],
                'param': r[1],
                'result': r[2],
                'timestamp': r[3]
            } for r in results
        ]

class StorageFactory:
    _storage_backend = None
    
    @classmethod
    def set_backend(cls, backend):
        cls._storage_backend = backend
    
    @classmethod
    def get_backend(cls):
        if cls._storage_backend is None:
            cls._storage_backend = FileStorageBackend()
        return cls._storage_backend

def _get_config_from_env(storage_type):
    if storage_type == 'file':
        return {
            'base_path': os.getenv('BENCHMARK_STORAGE_PATH', './storage')
        }
    elif storage_type == 'database':
        return {
            'db_type': os.getenv('BENCHMARK_DB_TYPE', 'sqlite'),
            'db_host': os.getenv('BENCHMARK_DB_HOST', 'localhost'),
            'db_port': os.getenv('BENCHMARK_DB_PORT', '5432'),
            'db_name': os.getenv('BENCHMARK_DB_NAME', 'benchmark'),
            'db_user': os.getenv('BENCHMARK_DB_USER', 'user'),
            'db_password': os.getenv('BENCHMARK_DB_PASSWORD', ''),
            'db_path': os.getenv('BENCHMARK_DB_PATH', './benchmark.db')
        }
    return {}

def init(app, storage_type=None, storage_config=None):
    if storage_type is None:
        storage_type = os.getenv('BENCHMARK_STORAGE_TYPE', 'file')
    
    if storage_config is None:
        storage_config = _get_config_from_env(storage_type)
    
    env_config = _get_config_from_env(storage_type)
    for key, value in env_config.items():
        if key not in storage_config:
            storage_config[key] = value
    
    if storage_type == 'file':
        backend = FileStorageBackend(storage_config.get('base_path', './storage'))
    elif storage_type == 'database':
        db_type = storage_config.get('db_type', 'sqlite')
        if db_type == 'sqlite':
            import helpers.db_sqlite
            backend = DatabaseStorageBackend(helpers.db_sqlite, db_type='sqlite')
        elif db_type == 'mysql':
            import helpers.db_mysql
            backend = DatabaseStorageBackend(helpers.db_mysql, db_type='mysql')
        elif db_type == 'postgresql':
            import helpers.db_postgresql
            backend = DatabaseStorageBackend(helpers.db_postgresql, db_type='postgresql')
        else:
            import helpers.db_sqlite
            backend = DatabaseStorageBackend(helpers.db_sqlite, db_type='sqlite')
    else:
        backend = FileStorageBackend()
    
    StorageFactory.set_backend(backend)

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

        import helpers.db_sqlite

        sql = f'SELECT username from USERS where password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (bar,))
        result = helpers.db_sqlite.results(cur, sql)
        RESPONSE += result
        con.close()
        
        storage = StorageFactory.get_backend()
        storage.save_query_result('BenchmarkTest00011', param, result)

        return RESPONSE