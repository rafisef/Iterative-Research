from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import codecs
import os

_BENCHMARK_COOKIE_CONFIG = {
    'max_age': 180,
    'secure': True,
    'domain': 'localhost'
}

_BAR = "This_should_always_happen"
_FILE_PATH = f'{TESTFILES_DIR}/{_BAR}'
_FILE_EXISTS = os.path.exists(_FILE_PATH)
_STATUS_MESSAGE = 'already exists' if _FILE_EXISTS else "doesn't exist yet"
_ESCAPED_FILE_PATH = escape_for_html(_FILE_PATH)
_POST_RESPONSE = f"Access to file: '{_ESCAPED_FILE_PATH}' created. And file {_STATUS_MESSAGE}."

def init(app):
	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
	def BenchmarkTest00004():
		if request.method == 'GET':
			response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
			response.set_cookie('BenchmarkTest00004', 'Filename',
				path=request.path,
				**_BENCHMARK_COOKIE_CONFIG)
			return response
		
		return _POST_RESPONSE