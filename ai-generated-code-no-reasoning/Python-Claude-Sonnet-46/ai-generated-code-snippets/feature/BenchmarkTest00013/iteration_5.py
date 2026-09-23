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
import threading
import time
import logging

logger = logging.getLogger(__name__)


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


def _get_env_float(key, default):
    try:
        return float(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


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
        "ASYNC_TIMEOUT": _get_env_float("BENCHMARK_ASYNC_TIMEOUT", 30.0),
        "RETRY_COUNT": _get_env_int("BENCHMARK_RETRY_COUNT", 3),
        "RETRY_DELAY": _get_env_float("BENCHMARK_RETRY_DELAY", 0.5),
        "ENABLE_CACHE": _get_env_bool("BENCHMARK_ENABLE_CACHE", False),
        "CACHE_TTL": _get_env_int("BENCHMARK_CACHE_TTL", 60),
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
ASYNC_TIMEOUT = config["ASYNC_TIMEOUT"]
RETRY_COUNT = config["RETRY_COUNT"]
RETRY_DELAY = config["RETRY_DELAY"]
ENABLE_CACHE = config["ENABLE_CACHE"]
CACHE_TTL = config["CACHE_TTL"]

_cache = {}
_cache_lock = threading.Lock()
_async_loop = None
_async_loop_lock = threading.Lock()


def _get_or_create_event_loop():
    global _async_loop
    with _async_loop_lock:
        if _async_loop is None or _async_loop.is_closed():
            _async_loop = asyncio.new_event_loop()
            t = threading.Thread(target=_async_loop.run_forever, daemon=True)
            t.start()
        return _async_loop


def _cache_get(key):
    if not ENABLE_CACHE:
        return None
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        value, expiry = entry
        if time.time() > expiry:
            del _cache[key]
            return None
        return value


def _cache_set(key, value):
    if not ENABLE_CACHE:
        return
    with _cache_lock:
        _cache[key] = (value, time.time() + CACHE_TTL)


def _cache_invalidate(key=None):
    with _cache_lock:
        if key is None:
            _cache.clear()
        elif key in _cache:
            del _cache[key]


def reload_config():
    global config, executor
    global COOKIE_NAME, COOKIE_VALUE, COOKIE_MAX_AGE, COOKIE_SECURE, COOKIE_DOMAIN
    global COOKIE_DEFAULT_VALUE, BENCHMARK_ROUTE_PREFIX, BENCHMARK_USE_ASYNC_DEFAULT
    global XML_FILE_PATH, STORAGE_BACKEND, DB_PATH
    global ASYNC_TIMEOUT, RETRY_COUNT, RETRY_DELAY, ENABLE_CACHE, CACHE_TTL

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
    ASYNC_TIMEOUT = config["ASYNC_TIMEOUT"]
    RETRY_COUNT = config["RETRY_COUNT"]
    RETRY_DELAY = config["RETRY_DELAY"]
    ENABLE_CACHE = config["ENABLE_CACHE"]
    CACHE_TTL = config["CACHE_TTL"]

    _cache_invalidate()


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
    cache_key = f"db:{bar}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

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
        result = (True, query, node_strings)
        _cache_set(cache_key, result)
        return result
    except Exception:
        query = f"SELECT firstname, lastname, department, salary FROM employees WHERE emplid = '{bar}'"
        return False, query, []


def parse_xml_and_query(bar):
    cache_key = f"xml:{bar}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        root = ET.parse(XML_FILE_PATH)
        query = f"/Employees/Employee[@emplid=\'{bar}\']"
        nodes = elementpath.select(root, query)
        node_strings = []
        for node in nodes:
            node_strings.append(' '.join([e.text for e in node]))
        result = (True, query, node_strings)
        _cache_set(cache_key, result)
        return result
    except Exception:
        query = f"/Employees/Employee[@emplid=\'{bar}\']"
        return False, query, []


def query_storage(bar):
    if STORAGE_BACKEND == "database":
        return query_db(bar)
    return parse_xml_and_query(bar)


def query_storage_with_retry(bar, retries=None, delay=None):
    retries = retries if retries is not None else RETRY_COUNT
    delay = delay if delay is not None else RETRY_DELAY
    last_result = None
    for attempt in range(max(1, retries)):
        result = query_storage(bar)
        last_result = result
        if result[0]:
            return result
        if attempt < retries - 1:
            time.sleep(delay)
    return last_result


async def async_query_storage(bar):
    loop = asyncio.get_event_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(executor, query_storage_with_retry, bar),
        timeout=ASYNC_TIMEOUT
    )
    return result


async def async_parse_xml_and_query(bar):
    loop = asyncio.get_event_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(executor, parse_xml_and_query, bar),
        timeout=ASYNC_TIMEOUT
    )
    return result


async def async_query_db(bar):
    loop = asyncio.get_event_loop()
    result = await asyncio.wait_for(
        loop.run_in_executor(executor, query_db, bar),
        timeout=ASYNC_TIMEOUT
    )
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
    success, query, node_strings = query_storage_with_retry(bar)
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
    try:
        success, query, node_strings = await async_query_storage(bar)
    except asyncio.TimeoutError:
        return f'Error: Query timed out after {ASYNC_TIMEOUT} seconds.'
    except Exception as e:
        return f'Error: Unexpected error during async query.'
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


async def build_response_async_xml(param):
    bar = await process_param_async(param)
    try:
        success, query, node_strings = await async_parse_xml_and_query(bar)
    except asyncio.TimeoutError:
        return f'Error: XML query timed out after {ASYNC_TIMEOUT} seconds.'
    except Exception:
        return f'Error: Unexpected error during async XML query.'
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


async def build_response_async_db(param):
    bar = await process_param_async(param)
    try:
        success, query, node_strings = await async_query_db(bar)
    except asyncio.TimeoutError:
        return f'Error: DB query timed out after {ASYNC_TIMEOUT} seconds.'
    except Exception:
        return f'Error: Unexpected error during async DB query.'
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


async def build_response_async_parallel(params):
    tasks = [build_response_async(p) for p in params]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    responses = []
    for r in results:
        if isinstance(r, Exception):
            responses.append(f'Error: {escape_for_html