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
import time

logger = logging.getLogger(__name__)

ALLOWED_FILES = {
    'This_should_always_happen': hashlib.sha256(b'This_should_always_happen').hexdigest()
}

COOKIE_SECRET = os.environ.get('COOKIE_SECRET')
if not COOKIE_SECRET:
    raise ValueError("COOKIE_SECRET environment variable must be set")

MAX_FILE_SIZE = 1024 * 1024
COOKIE_MAX_AGE = 60 * 3
MAX_PARAM_LENGTH = 255
RATE_LIMIT_ATTEMPTS = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_ATTEMPTS = 5

def rate_limit_check(identifier):
    current_time = time.time()
    if identifier not in RATE_LIMIT_ATTEMPTS:
        RATE_LIMIT_ATTEMPTS[identifier] = []
    
    RATE_LIMIT_ATTEMPTS[identifier] = [
        t for t in RATE_LIMIT_ATTEMPTS[identifier] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    
    if len(RATE_LIMIT_ATTEMPTS[identifier]) >= RATE_LIMIT_MAX_ATTEMPTS:
        return False
    
    RATE_LIMIT_ATTEMPTS[identifier].append(current_time)
    return True

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		client_id = request.remote_addr
		if not rate_limit_check(f"get_{client_id}"):
			logger.warning(f"Rate limit exceeded for {client_id}")
			return "Too many requests", 429
		
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
		client_id = request.remote_addr
		if not rate_limit_check(f"post_{client_id}"):
			logger.warning(f"Rate limit exceeded for {client_id}")
			return "Too many requests", 429
		
		RESPONSE = ""

		cookie_value = request.cookies.get("BenchmarkTest00004", "")
		
		if not cookie_value or not isinstance(cookie_value, str):
			logger.warning(f"Invalid cookie received from {client_id}")
			return "Invalid input", 400
		
		if len(cookie_value) > 512:
			logger.warning(f"Cookie value too long from {client_id}")
			return "Invalid input", 400
		
		try:
			parts = cookie_value.rsplit('.', 1)
			if len(parts) != 2:
				raise ValueError("Invalid cookie format")
			token, signature = parts
		except ValueError:
			logger.warning(f"Malformed cookie format from {client_id}")
			return "Invalid input", 400
		
		if not token or len(token) > 256:
			logger.warning(f"Invalid token from {client_id}")
			return "Invalid input", 400
		
		if not signature or len(signature) != 64:
			logger.warning(f"Invalid signature from {client_id}")
			return "Invalid input", 400
		
		expected_signature = hmac.new(COOKIE_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
		if not hmac.compare_digest(signature, expected_signature):
			logger.warning(f"Cookie signature validation failed from {client_id}")
			return "Invalid input", 400
		
		try:
			param = urllib.parse.unquote_plus(token)
		except Exception as e:
			logger.warning(f"URL decode error from {client_id}: {type(e).__name__}")
			return "Invalid input", 400
		
		if not param or len(param) > MAX_PARAM_LENGTH:
			logger.warning(f"Invalid parameter received from {client_id}")
			return "Invalid input", 400

		num = 106
		
		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		try:
			if bar not in ALLOWED_FILES:
				logger.warning(f"Unauthorized file access attempt from {client_id}")
				raise ValueError("File access not allowed")
			
			base_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
			target_path = (base_dir / bar).resolve()
			
			if not str(target_path).startswith(str(base_dir)):
				logger.warning(f"Path traversal attempt detected from {client_id}")
				raise ValueError("Path traversal attempt detected")
			
			if not target_path.exists():
				RESPONSE += " But file doesn't exist yet."
				return RESPONSE

			if not target_path.is_file():
				logger.warning(f"Target is not a file from {client_id}")
				raise ValueError("Target is not a file")

			file_size = target_path.stat().st_size
			if file_size > MAX_FILE_SIZE:
				logger.warning(f"File size exceeds limit from {client_id}")
				raise ValueError("File too large")

			try:
				with open(target_path, 'r', encoding='utf-8', errors='strict') as fileTarget:
					RESPONSE += (
						f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
					)
			except (IOError, OSError, UnicodeDecodeError) as e:
				logger.error(f"File read error from {client_id}: {type(e).__name__}")
				RESPONSE += " File access error."
				return RESPONSE

			RESPONSE += (
				" And file already exists."
			)

		except ValueError as e:
			logger.warning(f"ValueError from {client_id}: {str(e)}")
			RESPONSE += " Invalid file path."
		except Exception as e:
			logger.error(f"Unexpected error from {client_id}: {type(e).__name__}")
			RESPONSE += " An error occurred."

		return RESPONSE