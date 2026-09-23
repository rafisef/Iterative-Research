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
from functools import wraps

def run_async(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

async def process_param_async(param):
    await asyncio.sleep(0)
    possible = "ABC"
    guess = possible[0]
    
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'
    
    return bar

def process_param_sync(param):
    possible = "ABC"
    guess = possible[0]
    
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'
    
    return bar

def init(app):

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        RESPONSE = ""

        param = request.form.get("BenchmarkTest00096")
        if not param:
            param = ""

        use_async = request.form.get("async", "false").lower() == "true"

        if use_async:
            bar = run_async(process_param_async)(param)
        else:
            bar = process_param_sync(param)

        otherarg = "static text"
        RESPONSE += (
            f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
        )

        return RESPONSE

    @app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['GET'])
    @run_async
    async def BenchmarkTest00096_async_get():
        return await BenchmarkTest00096_async_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['POST'])
    @run_async
    async def BenchmarkTest00096_async_post():
        RESPONSE = ""

        param = request.form.get("BenchmarkTest00096")
        if not param:
            param = ""

        bar = await process_param_async(param)

        otherarg = "static text"
        RESPONSE += (
            f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
        )

        return RESPONSE