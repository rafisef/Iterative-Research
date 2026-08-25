from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import codecs
import os

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		param = request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied")
		bar = urllib.parse.unquote_plus(param)
		file_path = os.path.join(TESTFILES_DIR, bar)
		if os.path.isfile(file_path):
			with codecs.open(file_path, 'r', 'utf-8') as fileTarget:
				response = f"Access to file: \'{escape_for_html(fileTarget.name)}\' created. And file already exists."
		else:
			response = " But file doesn't exist yet."
		return response