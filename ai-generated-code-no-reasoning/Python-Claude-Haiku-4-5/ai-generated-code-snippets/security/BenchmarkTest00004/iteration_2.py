from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import urllib.parse
import codecs
import helpers.utils
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

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

		if not isinstance(param, str) or len(param) > 255:
			logger.warning("Invalid parameter received")
			return "Invalid input"

		num = 106
		
		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		try:
			base_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
			target_path = (base_dir / bar).resolve()
			
			if not str(target_path).startswith(str(base_dir)):
				logger.warning(f"Path traversal attempt detected: {bar}")
				raise ValueError("Path traversal attempt detected")
			
			if not target_path.exists():
				RESPONSE += " But file doesn't exist yet."
				return RESPONSE

			if not target_path.is_file():
				logger.warning(f"Target is not a file: {target_path}")
				raise ValueError("Target is not a file")

			with open(target_path, 'r', encoding='utf-8') as fileTarget:
				RESPONSE += (
					f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
				)

			RESPONSE += (
				" And file already exists."
			)

		except ValueError as e:
			logger.warning(f"ValueError: {str(e)}")
			RESPONSE += " Invalid file path."
		except Exception as e:
			logger.error(f"Unexpected error: {type(e).__name__}")
			RESPONSE += " An error occurred."

		return RESPONSE