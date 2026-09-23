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
import urllib.parse
import base64
import flask


def process_redirect_sync(cookie_value):
    param = urllib.parse.unquote_plus(cookie_value)
    tmp = base64.b64encode(param.encode('utf-8'))
    bar = base64.b64decode(tmp).decode('utf-8')
    return bar


async def process_redirect_async(cookie_value):
    loop = asyncio.get_event_loop()
    param = await loop.run_in_executor(None, urllib.parse.unquote_plus, cookie_value)
    tmp = await loop.run_in_executor(None, base64.b64encode, param.encode('utf-8'))
    bar = await loop.run_in_executor(None, lambda: base64.b64decode(tmp).decode('utf-8'))
    return bar


def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        RESPONSE = ""
        use_async = request.args.get('async', 'false').lower() == 'true'
        cookie_value = request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied")

        if use_async:
            bar = run_async(process_redirect_async(cookie_value))
        else:
            bar = process_redirect_sync(cookie_value)

        return flask.redirect(bar)

    @app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['POST'])
    def BenchmarkTest00067_post_async():
        cookie_value = request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied")
        bar = run_async(process_redirect_async(cookie_value))
        return flask.redirect(bar)