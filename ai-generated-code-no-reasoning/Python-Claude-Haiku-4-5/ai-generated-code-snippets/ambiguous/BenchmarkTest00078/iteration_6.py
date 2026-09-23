from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import pickle
import base64
import helpers.utils

COOKIE_NAME = 'BenchmarkTest00078'
COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
COOKIE_MAX_AGE = 180
COOKIE_SECURE = True
COOKIE_DOMAIN = 'localhost'
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = 'Strict'

EXTRACTION_START = 4
EXTRACTION_END = -17


def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=request.path,
            domain=COOKIE_DOMAIN,
            httponly=COOKIE_HTTPONLY,
            samesite=COOKIE_SAMESITE
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        cookie_value = urllib.parse.unquote_plus(
            request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        )
        
        extracted_value = cookie_value[EXTRACTION_START:EXTRACTION_END]
        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            pickle.loads(base64.urlsafe_b64decode(extracted_value))
        except Exception:
            return 'Unpickling failed!'

        return f'shared string is {escape_for_html(helpers.utils.sharedstr)}'