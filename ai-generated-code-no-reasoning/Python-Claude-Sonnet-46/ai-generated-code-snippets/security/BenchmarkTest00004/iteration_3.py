from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import codecs
import os
import helpers.utils
import re
import secrets

ALLOWED_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$')
MAX_FILENAME_LENGTH = 64
ALLOWED_EXTENSIONS = frozenset(['txt', 'log', 'csv', 'json'])

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		token = secrets.token_hex(32)
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		response.set_cookie('csrf_token', token,
			max_age=60*3,
			secure=True,
			httponly=False,
			samesite='Strict')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		RESPONSE = ""

		raw_cookie = request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied")

		if not raw_cookie or len(raw_cookie) > MAX_FILENAME_LENGTH * 3:
			return "Invalid cookie value.", 400

		try:
			param = urllib.parse.unquote_plus(raw_cookie)
		except Exception:
			return "Invalid cookie value.", 400

		num = 106

		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		bar = os.path.basename(bar)

		bar = bar.strip()

		if not bar or bar in ('.', '..'):
			return "Invalid file path.", 400

		if len(bar) > MAX_FILENAME_LENGTH:
			return "Invalid file path.", 400

		if not ALLOWED_FILENAME_PATTERN.match(bar):
			return "Invalid file path.", 400

		ext = bar.rsplit('.', 1)[-1].lower() if '.' in bar else ''
		if ext not in ALLOWED_EXTENSIONS:
			return "Invalid file path.", 400

		base_path = os.path.realpath(helpers.utils.TESTFILES_DIR)

		if not os.path.isdir(base_path):
			return "An error occurred.", 500

		safe_path = os.path.realpath(os.path.join(base_path, bar))

		if not safe_path.startswith(base_path + os.sep):
			return "Invalid file path.", 400

		if os.path.islink(safe_path):
			return "Invalid file path.", 400

		try:
			with codecs.open(safe_path, 'r', 'utf-8') as fileTarget:
				safe_filename = escape_for_html(os.path.basename(fileTarget.name))
				RESPONSE += (
					f"Access to file: \'{safe_filename}\' created."
				)
				RESPONSE += (
					" And file already exists."
				)

		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)
		except PermissionError:
			return "Access denied.", 403
		except Exception:
			return "An error occurred.", 500

		return RESPONSE