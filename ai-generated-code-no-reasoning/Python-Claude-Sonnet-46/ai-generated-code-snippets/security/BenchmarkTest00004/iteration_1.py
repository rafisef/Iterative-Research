from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import codecs
import os
import helpers.utils

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied"))

		num = 106

		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		bar = os.path.basename(bar)

		safe_path = os.path.realpath(os.path.join(helpers.utils.TESTFILES_DIR, bar))
		base_path = os.path.realpath(helpers.utils.TESTFILES_DIR)

		if not safe_path.startswith(base_path + os.sep):
			return "Invalid file path.", 400

		try:
			fileTarget = codecs.open(safe_path, 'r', 'utf-8')

			RESPONSE += (
				f"Access to file: \'{escape_for_html(os.path.basename(fileTarget.name))}\' created."
			)

			RESPONSE += (
				" And file already exists."
			)

			fileTarget.close()

		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)

		return RESPONSE