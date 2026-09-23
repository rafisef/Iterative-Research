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

def init(app):
	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
	def BenchmarkTest00004():
		if request.method == 'GET':
			response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
			response.set_cookie('BenchmarkTest00004', 'Filename',
				path=request.path,
				**_BENCHMARK_COOKIE_CONFIG)
			return response
		
		bar = "This_should_always_happen"
		file_path = f'{TESTFILES_DIR}/{bar}'
		
		return f"Access to file: '{escape_for_html(file_path)}' created. And file {'already exists' if os.path.exists(file_path) else \"doesn't exist yet\"}."