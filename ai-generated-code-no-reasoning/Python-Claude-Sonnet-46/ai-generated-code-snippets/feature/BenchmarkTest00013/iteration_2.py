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

executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.environ.get("BENCHMARK_THREAD_POOL_SIZE", concurrent.futures.ThreadPoolExecutor()._max_workers))
)

COOKIE_NAME = os.environ.get("BENCHMARK_COOKIE_NAME", "BenchmarkTest00013")
COOKIE_VALUE = os.environ.get("BENCHMARK_COOKIE_VALUE", "2222")
COOKIE_MAX_AGE = int(os.environ.get("BENCHMARK_COOKIE_MAX_AGE", str(60 * 3)))
COOKIE_SECURE = os.environ.get("BENCHMARK_COOKIE_SECURE", "true").lower() == "true"
COOKIE_DOMAIN = os.environ.get("BENCHMARK_COOKIE_DOMAIN", "localhost")
COOKIE_DEFAULT_VALUE = os.environ.get("BENCHMARK_COOKIE_DEFAULT_VALUE", "noCookieValueSupplied")
BENCHMARK_ROUTE_PREFIX = os.environ.get("BENCHMARK_ROUTE_PREFIX", "/benchmark/xpathi-00/BenchmarkTest00013")
BENCHMARK_USE_ASYNC_DEFAULT = os.environ.get("BENCHMARK_USE_ASYNC_DEFAULT", "false").lower() == "true"
XML_FILE_PATH = os.environ.get("BENCHMARK_XML_FILE_PATH", f"{helpers.utils.RES_DIR}/employees.xml")

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
    success, query, node_strings = parse_xml_and_query(bar)
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
    success, query, node_strings = await async_parse_xml_and_query(bar)
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