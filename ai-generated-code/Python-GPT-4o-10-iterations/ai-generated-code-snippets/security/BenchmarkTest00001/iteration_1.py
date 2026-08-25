from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html, is_safe_path

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
    def BenchmarkTest00001_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie('BenchmarkTest00001', 'Filename',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost',
            httponly=True)
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
    def BenchmarkTest00001_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

        bar = param

        import codecs
        import helpers.utils

        if not is_safe_path(helpers.utils.TESTFILES_DIR, bar):
            abort(400, description="Invalid file path")

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