from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import codecs

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied"))
		bar = "This_should_always_happen"

		try:
			fileTarget = codecs.open(f'{TESTFILES_DIR}/{bar}','r','utf-8')
			RESPONSE = f"Access to file: '{escape_for_html(fileTarget.name)}' created. And file already exists."
			fileTarget.close()
		except FileNotFoundError:
			RESPONSE = " But file doesn't exist yet."

		return RESPONSE