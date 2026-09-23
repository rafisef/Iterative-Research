from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import codecs

_COOKIE_MAX_AGE = 180
_BAR_VALUE = "This_should_always_happen"
_FILE_PATH = f'{TESTFILES_DIR}/{_BAR_VALUE}'

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
		try:
			with codecs.open(_FILE_PATH, 'r', 'utf-8') as fileTarget:
				return f"Access to file: \'{escape_for_html(fileTarget.name)}\' created. And file already exists."
		except FileNotFoundError:
			return "Access to file: created. But file doesn't exist yet."