from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import urllib.parse
import codecs
import helpers.utils
from pathlib import Path
import logging
import secrets
import hashlib
import hmac

logger = logging.getLogger(__name__)

ALLOWED_FILES = {
    'This_should_always_happen': hashlib.sha256(b'This_should_always_happen').hexdigest()
}

COOKIE_SECRET = os.environ.get('COOKIE_SECRET', secrets.token_hex(32))
MAX_FILE_SIZE = 1024 * 1024
COOKIE_MAX_AGE = 60 * 3

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		token = secrets.token_urlsafe(32)
		token_signature = hmac.new(COOKIE_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
		cookie_value = f"{token}.{token_signature}"
		response.set_cookie('BenchmarkTest00004', cookie_value,
			max_age=COOKIE_MAX_AGE,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		RESPONSE = ""

		cookie_value = request.cookies.get("BenchmarkTest00004", "")
		
		if not cookie_value or not isinstance(cookie_value, str):
			logger.warning("Invalid cookie received")
			return "Invalid input"
		
		try:
			token, signature = cookie_value.rsplit('.', 1)
		except ValueError:
			logger.warning("Malformed cookie format")
			return "Invalid input"
		
		expected_signature = hmac.new(COOKIE_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
		if not hmac.compare_digest(signature, expected_signature):
			logger.warning("Cookie signature validation failed")
			return "Invalid input"
		
		param = urllib.parse.unquote_plus(token)
		
		if not param or len(param) > 255:
			logger.warning("Invalid parameter received")
			return "Invalid input"

		num = 106
		
		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		try:
			if bar not in ALLOWED_FILES:
				logger.warning(f"Unauthorized file access attempt")
				raise ValueError("File access not allowed")
			
			base_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
			target_path = (base_dir / bar).resolve()
			
			if not str(target_path).startswith(str(base_dir)):
				logger.warning(f"Path traversal attempt detected")
				raise ValueError("Path traversal attempt detected")
			
			if not target_path.exists():
				RESPONSE += " But file doesn't exist yet."
				return RESPONSE

			if not target_path.is_file():
				logger.warning(f"Target is not a file")
				raise ValueError("Target is not a file")

			file_size = target_path.stat().st_size
			if file_size > MAX_FILE_SIZE:
				logger.warning(f"File size exceeds limit")
				raise ValueError("File too large")

			try:
				with open(target_path, 'r', encoding='utf-8', errors='strict') as fileTarget:
					RESPONSE += (
						f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
					)
			except (IOError, OSError, UnicodeDecodeError) as e:
				logger.error(f"File read error: {type(e).__name__}")
				RESPONSE += " File access error."
				return RESPONSE

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