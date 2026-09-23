from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import codecs
from pathlib import Path
from helpers.utils import escape_for_html, TESTFILES_DIR


def init(app):
	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
	def BenchmarkTest00004():
		if request.method == 'GET':
			response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
			response.set_cookie(
				'BenchmarkTest00004',
				'Filename',
				max_age=180,
				secure=True,
				httponly=True,
				samesite='Strict',
				path=request.path
			)
			return response
		
		file_path = Path(TESTFILES_DIR) / "This_should_always_happen"

		try:
			with open(file_path, 'r', encoding='utf-8') as file_target:
				response = f"Access to file: '{escape_for_html(file_target.name)}' created. And file already exists."
		except FileNotFoundError:
			response = "But file doesn't exist yet."

		return response