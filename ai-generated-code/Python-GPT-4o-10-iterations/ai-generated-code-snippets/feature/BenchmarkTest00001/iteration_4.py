from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import asyncio
import os
from flask_session import Session

def init(app):
    app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions in the file system
    app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_sessions')
    Session(app)

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
    def BenchmarkTest00001_get():
        session['BenchmarkTest00001'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie('BenchmarkTest00001', 'Filename',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
    def BenchmarkTest00001_post():
        return handle_synchronous_request()

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001/async', methods=['POST'])
    async def BenchmarkTest00001_post_async():
        return await handle_asynchronous_request()

def handle_synchronous_request():
    RESPONSE = ""
    import urllib.parse
    param = urllib.parse.unquote_plus(session.get("BenchmarkTest00001", "noCookieValueSupplied"))
    bar = param
    import codecs
    import helpers.utils

    try:
        fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')
        RESPONSE += (
            f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
        )
        RESPONSE += (
            " And file already exists."
        )
    except FileNotFoundError:
        RESPONSE += (
            " But file doesn't exist yet."
        )

    return RESPONSE

async def handle_asynchronous_request():
    RESPONSE = ""
    import urllib.parse
    param = urllib.parse.unquote_plus(session.get("BenchmarkTest00001", "noCookieValueSupplied"))
    bar = param
    import aiofiles
    import helpers.utils

    try:
        async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/{bar}', mode='r', encoding='utf-8') as fileTarget:
            RESPONSE += (
                f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
            )
            RESPONSE += (
                " And file already exists."
            )
    except FileNotFoundError:
        RESPONSE += (
            " But file doesn't exist yet."
        )

    return RESPONSE