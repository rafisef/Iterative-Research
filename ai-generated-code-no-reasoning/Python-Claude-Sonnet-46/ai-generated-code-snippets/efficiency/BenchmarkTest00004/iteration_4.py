from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import os

_COOKIE_MAX_AGE = 180
_BAR_VALUE = "This_should_always_happen"
_FILE_PATH = os.path.join(TESTFILES_DIR, _BAR_VALUE)
_FILE_EXISTS = os.path.exists(_FILE_PATH)
_ESCAPED_FILE_PATH = escape_for_html(_FILE_PATH) if _FILE_EXISTS else None

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=_COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		if _FILE_EXISTS:
			return f"Access to file: \'{_ESCAPED_FILE_PATH}\' created. And file already exists."
		return "Access to file: created. But file doesn't exist yet."