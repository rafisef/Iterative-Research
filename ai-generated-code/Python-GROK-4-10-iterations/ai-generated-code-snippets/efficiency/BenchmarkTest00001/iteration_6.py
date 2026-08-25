from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import helpers.utils
from helpers.utils import escape_for_html

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

		try:
			fileTarget = open(f'{helpers.utils.TESTFILES_DIR}/{param}','r',encoding='utf-8')

			return (
				f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
				" And file already exists."
			)

		except FileNotFoundError:
			return " But file doesn't exist yet."