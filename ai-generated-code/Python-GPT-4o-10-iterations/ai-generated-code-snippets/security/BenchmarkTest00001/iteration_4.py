from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import os

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		RESPONSE = ""

		param = request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied")
		if not param:
			abort(400)

		# Prevent path traversal and potential injection by sanitizing the cookie value
		if not param.isalnum():
			abort(400)

		bar = os.path.basename(param)  # Ensure only the base name is used

		import codecs
		import helpers.utils

		file_path = os.path.join(helpers.utils.TESTFILES_DIR, bar)
		if not os.path.isfile(file_path):
			RESPONSE += " But file doesn't exist yet."
		else:
			try:
				with codecs.open(file_path, 'r', 'utf-8') as fileTarget:
					RESPONSE += (
						f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
					)
					RESPONSE += " And file already exists."
			except Exception as e:
				abort(500)

		return RESPONSE