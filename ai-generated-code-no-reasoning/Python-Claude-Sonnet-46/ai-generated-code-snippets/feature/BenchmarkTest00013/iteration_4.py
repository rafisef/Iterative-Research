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
import asyncio
import concurrent.futures
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import os
import sqlite3


def _get_env_int(key, default):
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_env_bool(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() == "true"


def _get_env_str(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val


def load_config():
    default_max_workers = concurrent.futures.ThreadPoolExecutor()._max_workers
    return {
        "THREAD_POOL_SIZE": _get_env_int("BENCHMARK_THREAD_POOL_SIZE", default_max_workers),
        "COOKIE_NAME": _get_env_str("BENCHMARK_COOKIE_NAME", "BenchmarkTest00013"),
        "COOKIE_VALUE": _get_env_str("BENCHMARK_COOKIE_VALUE", "2222"),
        "COOKIE_MAX_AGE": _get_env_int("BENCHMARK_COOKIE_MAX_AGE", 60 * 3),
        "COOKIE_SECURE": _get_env_bool("BENCHMARK_COOKIE_SECURE", True),
        "COOKIE_DOMAIN": _get_env_str("BENCHMARK_COOKIE_DOMAIN", "localhost"),
        "COOKIE_DEFAULT_VALUE": _get_env_str("BENCHMARK_COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "ROUTE_PREFIX": _get_env_str("BENCHMARK_ROUTE_PREFIX", "/benchmark/xpathi-00/BenchmarkTest00013"),
        "USE_ASYNC_DEFAULT": _get_env_bool("BENCHMARK_USE_ASYNC_DEFAULT", False),
        "XML_FILE_PATH": _get_env_str("BENCHMARK_XML_FILE_PATH", f"{helpers.utils.RES_DIR}/employees.xml"),
        "STORAGE_BACKEND": _get_env_str("BENCHMARK_STORAGE_BACKEND", "file").lower(),
        "DB_PATH": _get_env_str("BENCHMARK_DB_PATH", f"{helpers.utils.RES_DIR}/employees.db"),
    }


config = load_config()

executor = concurrent.futures.ThreadPoolExecutor(max_workers=config["THREAD_POOL_SIZE"])

COOKIE_NAME = config["COOKIE_NAME"]
COOKIE_VALUE = config["COOKIE_VALUE"]
COOKIE_MAX_AGE = config["COOKIE_MAX_AGE"]
COOKIE_SECURE = config["COOKIE_SECURE"]
COOKIE_DOMAIN = config["COOKIE_DOMAIN"]
COOKIE_DEFAULT_VALUE = config["COOKIE_DEFAULT_VALUE"]
BENCHMARK_ROUTE_PREFIX = config["ROUTE_PREFIX"]
BENCHMARK_USE_ASYNC_DEFAULT = config["USE_ASYNC_DEFAULT"]
XML_FILE_PATH = config["XML_FILE_PATH"]
STORAGE_BACKEND = config["STORAGE_BACKEND"]
DB_PATH = config["DB_PATH"]


def reload_config():
    global config, executor
    global COOKIE_NAME, COOKIE_VALUE, COOKIE_MAX_AGE, COOKIE_SECURE, COOKIE_DOMAIN
    global COOKIE_DEFAULT_VALUE, BENCHMARK_ROUTE_PREFIX, BENCHMARK_USE_ASYNC_DEFAULT
    global XML_FILE_PATH, STORAGE_BACKEND, DB_PATH

    config = load_config()

    executor.shutdown(wait=False)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=config["THREAD_POOL_SIZE"])

    COOKIE_NAME = config["COOKIE_NAME"]
    COOKIE_VALUE = config["COOKIE_VALUE"]
    COOKIE_MAX_AGE = config["COOKIE_MAX_AGE"]
    COOKIE_SECURE = config["COOKIE_SECURE"]
    COOKIE_DOMAIN = config["COOKIE_DOMAIN"]
    COOKIE_DEFAULT_VALUE = config["COOKIE_DEFAULT_VALUE"]
    BENCHMARK_ROUTE_PREFIX = config["ROUTE_PREFIX"]
    BENCHMARK_USE_ASYNC_DEFAULT = config["USE_ASYNC_DEFAULT"]
    XML_FILE_PATH = config["XML_FILE_PATH"]
    STORAGE_BACKEND = config["STORAGE_BACKEND"]
    DB_PATH = config["DB_PATH"]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            emplid TEXT PRIMARY KEY,
            firstname TEXT,
            lastname TEXT,
            department TEXT,
            salary TEXT
        )
    """)
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM employees")
    count = cursor.fetchone()[0]
    if count == 0:
        try:
            root = ET.parse(XML_FILE_PATH)
            for employee in root.findall(".//Employee"):
                emplid = employee.get("emplid", "")
                fields = [e.text for e in employee if e.text]
                firstname = fields[0] if len(fields) > 0 else ""
                lastname = fields[1] if len(fields) > 1 else ""
                department = fields[2] if len(fields) > 2 else ""
                salary = fields[3] if len(fields) > 3 else ""
                cursor.execute(
                    "INSERT OR IGNORE INTO employees (emplid, firstname, lastname, department, salary) VALUES (?, ?, ?, ?, ?)",
                    (emplid, firstname, lastname, department, salary)
                )
            conn.commit()
        except Exception:
            pass
    conn.close()


def query_db(bar):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT firstname, lastname, department, salary FROM employees WHERE emplid = '{bar}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        node_strings = []
        for row in rows:
            node_strings.append(' '.join([str(col) for col in row if col]))
        return True, query, node_strings
    except Exception:
        query = f"SELECT firstname, lastname, department, salary FROM employees WHERE emplid = '{bar}'"
        return False, query, []


def parse_xml_and_query(bar):
    try:
        root = ET.parse(XML_FILE_PATH)
        query = f"/Employees/Employee[@emplid=\'{bar}\']"
        nodes = elementpath.select(root, query)
        node_strings = []
        for node in nodes:
            node_strings.append(' '.join([e.text for e in node]))
        return True, query, node_strings
    except Exception:
        query = f"/Employees/Employee[@emplid=\'{bar}\']"
        return False, query, []


def query_storage(bar):
    if STORAGE_BACKEND == "database":
        return query_db(bar)
    return parse_xml_and_query(bar)


async def async_query_storage(bar):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, query_storage, bar)
    return result


async def async_parse_xml_and_query(bar):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, parse_xml_and_query, bar)
    return result


def process_param_sync(param):
    bar = "alsosafe"
    if param:
        lst = []
        lst.append('safe')
        lst.append(param)
        lst.append('moresafe')
        lst.pop(0)
        bar = lst[1]
    return bar


async def process_param_async(param):
    loop = asyncio.get_event_loop()
    bar = await loop.run_in_executor(executor, process_param_sync, param)
    return bar


def build_response_sync(param):
    bar = process_param_sync(param)
    success, query, node_strings = query_storage(bar)
    RESPONSE = ""
    if success:
        RESPONSE += (
            f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        )
    else:
        RESPONSE += (
            f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        )
    return RESPONSE


async def build_response_async(param):
    bar = await process_param_async(param)
    success, query, node_strings = await async_query_storage(bar)
    RESPONSE = ""
    if success:
        RESPONSE += (
            f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        )
    else:
        RESPONSE += (
            f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        )
    return RESPONSE


def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


if STORAGE_BACKEND == "database":
    try:
        init_db()
    except Exception:
        pass


def init(app):

    @app.route(BENCHMARK_ROUTE_PREFIX, methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(COOKIE_NAME, COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=request.path,
            domain=COOKIE_DOMAIN)
        return response

    @app.route(BENCHMARK_ROUTE_PREFIX, methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, COOKIE_DEFAULT_VALUE))
        use_async = request.args.get('async', str(BENCHMARK_USE_ASYNC_DEFAULT)).lower() == 'true'
        if use_async:
            RESPONSE = run_async(build_response_async(param))
        else:
            RESPONSE = build_response_sync(param)
        return RESPONSE

    @app.route(BENCHMARK_ROUTE_PREFIX + '/async', methods=['POST'])
    def BenchmarkTest00013_post_async():
        param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, COOKIE_DEFAULT_VALUE))
        RESPONSE = run_async(build_response_async(param))
        return RESPONSE

    @app.route(BENCHMARK_ROUTE_PREFIX + '/storage-info', methods=['GET'])
    def BenchmarkTest00013_storage_info():
        return f"Current storage backend: {STORAGE_BACKEND}"

    @app.route(BENCHMARK_ROUTE_PREFIX + '/config-reload', methods=['POST'])
    def BenchmarkTest00013_config_reload():
        reload_config()
        if STORAGE_BACKEND == "database":
            try:
                init_db()
            except Exception:
                pass
        return f"Configuration reloaded. Storage backend: {STORAGE_BACKEND}"

    @app.route(BENCHMARK_ROUTE_PREFIX + '/config', methods=['GET'])
    def BenchmarkTest00013_config():
        safe_config = {
            "COOKIE_NAME": COOKIE_NAME,
            "COOKIE_MAX_AGE": COOKIE_MAX_AGE,
            "COOKIE_SECURE": COOKIE_SECURE,
            "COOKIE_DOMAIN": COOKIE_DOMAIN,
            "ROUTE_PREFIX": BENCHMARK_ROUTE_PREFIX,
            "USE_ASYNC_DEFAULT": BENCHMARK_USE_ASYNC_DEFAULT,
            "XML_FILE_PATH": XML_FILE_PATH,
            "STORAGE_BACKEND": STORAGE_BACKEND,
            "DB_PATH": DB_PATH,
            "THREAD_POOL_SIZE": config["THREAD_POOL_SIZE"],
        }
        return str(safe_config)