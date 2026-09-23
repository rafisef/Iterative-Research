from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import re
import helpers.utils as helpers

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie(
            'BenchmarkTest00004',
            'Filename',
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        RESPONSE = ''
        cookie_value = request.cookies.get('BenchmarkTest00004', 'noCookieValueSupplied')
        if not re.match(r'^[\w\-]+$', cookie_value):
            cookie_value = 'safe_default.txt'
        base_dir = os.path.abspath(helpers.TESTFILES_DIR)
        safe_path = os.path.realpath(os.path.join(base_dir, cookie_value))
        if not safe_path.startswith(base_dir):
            safe_path = os.path.join(base_dir, 'safe_default.txt')
        try:
            with open(safe_path, 'r', encoding='utf-8') as file_target:
                RESPONSE += f"Access to file: '{escape_for_html(file_target.name)}' created."
                RESPONSE += ' And file already exists.'
        except FileNotFoundError:
            RESPONSE += " But file doesn't exist yet."
        return RESPONSE