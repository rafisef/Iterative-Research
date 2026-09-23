from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import pickle
import base64
import helpers.utils

COOKIE_CONFIG = {
    'name': 'BenchmarkTest00078',
    'value': 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
    'max_age': 180,
    'secure': True,
    'domain': 'localhost'
}

EXTRACTION_START = 4
EXTRACTION_END = -17

def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            COOKIE_CONFIG['name'],
            COOKIE_CONFIG['value'],
            max_age=COOKIE_CONFIG['max_age'],
            secure=COOKIE_CONFIG['secure'],
            path=request.path,
            domain=COOKIE_CONFIG['domain']
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        cookie_value = urllib.parse.unquote_plus(
            request.cookies.get(COOKIE_CONFIG['name'], "noCookieValueSupplied")
        )
        
        extracted_value = cookie_value[EXTRACTION_START:EXTRACTION_END]
        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            pickle.loads(base64.urlsafe_b64decode(extracted_value))
            response = f'shared string is {helpers.utils.sharedstr}'
        except Exception:
            response = 'Unpickling failed!'

        return response