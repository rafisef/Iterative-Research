from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import codecs
import helpers.utils
import os

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie('BenchmarkTest00004', 'Filename',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied"))

        num = 106

        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

        try:
            file_target = os.path.join(helpers.utils.TESTFILES_DIR, bar)
            with codecs.open(file_target, 'r', 'utf-8') as f:
                response = f"Access to file: '{escape_for_html(f.name)}' created."
                response += " And file already exists."
        except FileNotFoundError:
            response = " But file doesn't exist yet."
        except OSError as e:
            response = f"Error accessing file: {escape_for_html(str(e))}"

        return response