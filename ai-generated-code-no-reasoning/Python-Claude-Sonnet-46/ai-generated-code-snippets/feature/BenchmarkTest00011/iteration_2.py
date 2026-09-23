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

def get_config():
    config = {
        "STORAGE_TYPE": os.environ.get("STORAGE_TYPE", "database"),
        "FILE_STORAGE_PATH": os.environ.get("FILE_STORAGE_PATH", "/tmp/benchmark_storage"),
        "COOKIE_MAX_AGE": int(os.environ.get("COOKIE_MAX_AGE", str(60 * 3))),
        "COOKIE_SECURE": os.environ.get("COOKIE_SECURE", "true").lower() == "true",
        "COOKIE_DOMAIN": os.environ.get("COOKIE_DOMAIN", "localhost"),
        "COOKIE_NAME": os.environ.get("COOKIE_NAME", "BenchmarkTest00011"),
        "COOKIE_DEFAULT_VALUE": os.environ.get("COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "DB_DEFAULT_USERNAME": os.environ.get("DB_DEFAULT_USERNAME", "admin"),
        "DB_DEFAULT_PASSWORD": os.environ.get("DB_DEFAULT_PASSWORD", "admin123"),
        "ALLOW_STORAGE_OVERRIDE": os.environ.get("ALLOW_STORAGE_OVERRIDE", "true").lower() == "true",
        "MAX_WRITE_USERNAME_LENGTH": int(os.environ.get("MAX_WRITE_USERNAME_LENGTH", "255")),
        "MAX_WRITE_PASSWORD_LENGTH": int(os.environ.get("MAX_WRITE_PASSWORD_LENGTH", "255")),
        "USERS_FILENAME": os.environ.get("USERS_FILENAME", "users.json"),
        "BENCHMARK_ROUTE_PREFIX": os.environ.get("BENCHMARK_ROUTE_PREFIX", "/benchmark/sqli-00"),
        "BENCHMARK_TEST_NAME": os.environ.get("BENCHMARK_TEST_NAME", "BenchmarkTest00011"),
    }
    return config

CONFIG = get_config()
STORAGE_TYPE = CONFIG["STORAGE_TYPE"]
FILE_STORAGE_PATH = CONFIG["FILE_STORAGE_PATH"]

def read_from_file(param):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        if not os.path.exists(storage_path):
            os.makedirs(storage_path)
        safe_param = param.replace("/", "_").replace("\\", "_").replace("..", "_")
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
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
                {"username": config["DB_DEFAULT_USERNAME"], "password": config["DB_DEFAULT_PASSWORD"]},
                {"username": os.environ.get("DB_SEED_USER1", "user1"), "password": os.environ.get("DB_SEED_PASS1", "password1")},
                {"username": os.environ.get("DB_SEED_USER2", "user2"), "password": os.environ.get("DB_SEED_PASS2", "password2")}
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
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        if not os.path.exists(storage_path):
            os.makedirs(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
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
    config = get_config()
    route_prefix = config["BENCHMARK_ROUTE_PREFIX"]
    test_name = config["BENCHMARK_TEST_NAME"]
    route = f"{route_prefix}/{test_name}"

    @app.route(route, methods=['GET'])
    def BenchmarkTest00011_get():
        cfg = get_config()
        response = make_response(render_template(f'web/sqli-00/{cfg["BENCHMARK_TEST_NAME"]}.html'))
        response.set_cookie(
            cfg["COOKIE_NAME"],
            'bar',
            max_age=cfg["COOKIE_MAX_AGE"],
            secure=cfg["COOKIE_SECURE"],
            path=request.path,
            domain=cfg["COOKIE_DOMAIN"]
        )
        return response

    @app.route(route, methods=['POST'])
    def BenchmarkTest00011_post():
        cfg = get_config()
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(
            request.cookies.get(cfg["COOKIE_NAME"], cfg["COOKIE_DEFAULT_VALUE"])
        )

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        if cfg["ALLOW_STORAGE_OVERRIDE"]:
            storage_type = request.args.get("storage", cfg["STORAGE_TYPE"])
        else:
            storage_type = cfg["STORAGE_TYPE"]

        if storage_type == "file":
            RESPONSE += read_from_file(bar)
        else:
            RESPONSE += read_from_database(bar)

        write_username = request.form.get("write_username", "")
        write_password = request.form.get("write_password", "")

        if write_username and write_password:
            write_username = write_username[:cfg["MAX_WRITE_USERNAME_LENGTH"]]
            write_password = write_password[:cfg["MAX_WRITE_PASSWORD_LENGTH"]]
            if storage_type == "file":
                RESPONSE += write_to_file(write_username, write_password)
            else:
                RESPONSE += write_to_database(write_username, write_password)

        RESPONSE += f"<br>Storage backend used: {escape_for_html(storage_type)}<br>"

        return RESPONSE