from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import pickle
import base64
import helpers.utils

COOKIE_NAME = 'BenchmarkTest00078'
COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'

def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(COOKIE_NAME, COOKIE_VALUE,
                            max_age=180, secure=True,
                            path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        cookie_val = request.cookies.get(COOKIE_NAME, 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_val)
        bar = param
        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
        except (pickle.UnpicklingError, ValueError, base64.binascii.Error):
            return 'Unpickling failed!'

        return f'shared string is {helpers.utils.sharedstr}'