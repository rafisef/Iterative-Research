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

executor = concurrent.futures.ThreadPoolExecutor()

def parse_xml_and_query(bar):
    try:
        root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
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

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie('BenchmarkTest00013', '2222',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        use_async = request.args.get('async', 'false').lower() == 'true'
        if use_async:
            RESPONSE = run_async(build_response_async(param))
        else:
            RESPONSE = build_response_sync(param)
        return RESPONSE

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['POST'])
    def BenchmarkTest00013_post_async():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        RESPONSE = run_async(build_response_async(param))
        return RESPONSE