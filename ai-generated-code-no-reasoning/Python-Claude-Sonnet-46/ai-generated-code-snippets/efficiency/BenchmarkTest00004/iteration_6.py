from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import os

_COOKIE_MAX_AGE = 180
_BAR_VALUE = "This_should_always_happen"

def _get_post_response():
    file_path = os.path.join(TESTFILES_DIR, _BAR_VALUE)
    if os.path.exists(file_path):
        return f"Access to file: '{escape_for_html(file_path)}' created. And file already exists."
    return "Access to file: created. But file doesn't exist yet."

_POST_RESPONSE = _get_post_response()

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
		return _POST_RESPONSE