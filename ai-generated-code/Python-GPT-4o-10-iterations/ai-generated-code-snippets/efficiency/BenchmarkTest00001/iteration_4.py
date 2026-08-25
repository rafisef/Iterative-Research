from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import codecs

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET', 'POST'])
	def BenchmarkTest00001():
		if request.method == 'GET':
			response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
			response.set_cookie('BenchmarkTest00001', 'Filename',
								max_age=180,
								secure=True,
								path=request.path,
								domain='localhost')
			return response

		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))
		bar = param

		try:
			with codecs.open(f'{TESTFILES_DIR}/{bar}', 'r', 'utf-8') as fileTarget:
				RESPONSE += f"Access to file: \'{escape_for_html(fileTarget.name)}\' created. And file already exists."
		except FileNotFoundError:
			RESPONSE += " But file doesn't exist yet."

		return RESPONSE