from flask import redirect, url_for, request, make_response, render_template, abort, current_app
from helpers.utils import escape_for_html, is_safe_path
import os

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
    def BenchmarkTest00001_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie('BenchmarkTest00001', 'Filename',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost',
            httponly=True,
            samesite='Strict')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
    def BenchmarkTest00001_post():
        RESPONSE = ""

        from urllib.parse import unquote_plus
        param = unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

        bar = param.replace('..', '')  # Prevent directory traversal

        import codecs
        import helpers.utils

        if not is_safe_path(helpers.utils.TESTFILES_DIR, bar):
            abort(400, description="Invalid file path")

        safe_path = os.path.join(helpers.utils.TESTFILES_DIR, bar)
        if not os.path.commonpath([helpers.utils.TESTFILES_DIR, safe_path]) == os.path.abspath(helpers.utils.TESTFILES_DIR):
            abort(400, description="Invalid file path")

        # Check for path traversal again after joining paths
        if not os.path.commonprefix([os.path.realpath(safe_path), os.path.realpath(helpers.utils.TESTFILES_DIR)]) == os.path.realpath(helpers.utils.TESTFILES_DIR):
            abort(400, description="Invalid file path")

        try:
            with codecs.open(safe_path, 'r', 'utf-8') as fileTarget:
                RESPONSE += (
                    f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
                )
                RESPONSE += " And file already exists."

        except FileNotFoundError:
            RESPONSE += " But file doesn't exist yet."

        except IOError:
            abort(500, description="Error accessing file")

        return RESPONSE