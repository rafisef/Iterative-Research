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
import json

STORAGE_TYPE = os.environ.get("STORAGE_TYPE", "database")
FILE_STORAGE_PATH = os.environ.get("FILE_STORAGE_PATH", "/tmp/benchmark_storage")

def read_from_file(param):
    result = ""
    try:
        if not os.path.exists(FILE_STORAGE_PATH):
            os.makedirs(FILE_STORAGE_PATH)
        safe_param = param.replace("/", "_").replace("\\", "_").replace("..", "_")
        file_path = os.path.join(FILE_STORAGE_PATH, "users.json")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                data = json.load(f)
            matches = [entry["username"] for entry in data if entry.get("password") == param]
            if matches:
                result += f"<br>Results for query: SELECT username from USERS where password = '{param}'<br>"
                for username in matches:
                    result += f"username: {username}<br>"
            else:
                result += f"<br>No results found for query: SELECT username from USERS where password = '{param}'<br>"
        else:
            default_data = [
                {"username": "admin", "password": "admin123"},
                {"username": "user1", "password": "password1"},
                {"username": "user2", "password": "password2"}
            ]
            with open(file_path, "w") as f:
                json.dump(default_data, f)
            result += "<br>File storage initialized with default data. No matching records found.<br>"
    except Exception as e:
        result += f"<br>File storage error: {escape_for_html(str(e))}<br>"
    return result

def read_from_database(param):
    result = ""
    import helpers.db_sqlite
    sql = f'SELECT username from USERS where password = ?'
    con = helpers.db_sqlite.get_connection()
    cur = con.cursor()
    cur.execute(sql, (param,))
    result += helpers.db_sqlite.results(cur, sql)
    con.close()
    return result

def write_to_file(username, password):
    result = ""
    try:
        if not os.path.exists(FILE_STORAGE_PATH):
            os.makedirs(FILE_STORAGE_PATH)
        file_path = os.path.join(FILE_STORAGE_PATH, "users.json")
        data = []
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                data = json.load(f)
        data.append({"username": username, "password": password})
        with open(file_path, "w") as f:
            json.dump(data, f)
        result += "<br>Record written to file storage successfully.<br>"
    except Exception as e:
        result += f"<br>File storage write error: {escape_for_html(str(e))}<br>"
    return result

def write_to_database(username, password):
    result = ""
    import helpers.db_sqlite
    sql = f'INSERT INTO USERS (username, password) VALUES (?, ?)'
    con = helpers.db_sqlite.get_connection()
    cur = con.cursor()
    cur.execute(sql, (username, password))
    con.commit()
    result += "<br>Record written to database storage successfully.<br>"
    con.close()
    return result

def init(app):

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

        storage_type = request.args.get("storage", STORAGE_TYPE)

        if storage_type == "file":
            RESPONSE += read_from_file(bar)
        else:
            RESPONSE += read_from_database(bar)

        write_username = request.form.get("write_username", "")
        write_password = request.form.get("write_password", "")

        if write_username and write_password:
            if storage_type == "file":
                RESPONSE += write_to_file(write_username, write_password)
            else:
                RESPONSE += write_to_database(write_username, write_password)

        RESPONSE += f"<br>Storage backend used: {escape_for_html(storage_type)}<br>"

        return RESPONSE