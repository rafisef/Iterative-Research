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
from functools import wraps
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

ALLOWED_FILES = {
    'This_should_always_happen': hashlib.sha256(b'This_should_always_happen').hexdigest()
}

COOKIE_SECRET = os.environ.get('COOKIE_SECRET')
if not COOKIE_SECRET or len(COOKIE_SECRET) < 32:
    raise ValueError("COOKIE_SECRET environment variable must be set and at least 32 characters")

MAX_FILE_SIZE = 1024 * 1024
COOKIE_MAX_AGE = 60 * 3
MAX_PARAM_LENGTH = 255
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_ATTEMPTS = 5

RATE_LIMIT_ATTEMPTS = defaultdict(list)
RATE_LIMIT_LOCK = threading.Lock()

def rate_limit_check(identifier):
    with RATE_LIMIT_LOCK:
        current_time = time.time()
        RATE_LIMIT_ATTEMPTS[identifier] = [
            t for t in RATE_LIMIT_ATTEMPTS[identifier] 
            if current_time - t < RATE_LIMIT_WINDOW
        ]
        
        if len(RATE_LIMIT_ATTEMPTS[identifier]) >= RATE_LIMIT_MAX_ATTEMPTS:
            return False
        
        RATE_LIMIT_ATTEMPTS[identifier].append(current_time)
        return True

def validate_cookie_signature(cookie_value, client_id):
    if not cookie_value or not isinstance(cookie_value, str):
        logger.warning(f"Invalid cookie received from {client_id}")
        return None
    
    if len(cookie_value) > 512:
        logger.warning(f"Cookie value too long from {client_id}")
        return None
    
    try:
        parts = cookie_value.rsplit('.', 1)
        if len(parts) != 2:
            raise ValueError("Invalid cookie format")
        token, signature = parts
    except ValueError:
        logger.warning(f"Malformed cookie format from {client_id}")
        return None
    
    if not token or len(token) > 256:
        logger.warning(f"Invalid token from {client_id}")
        return None
    
    if not signature or len(signature) != 64:
        logger.warning(f"Invalid signature from {client_id}")
        return None
    
    try:
        expected_signature = hmac.new(COOKIE_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()
    except Exception as e:
        logger.error(f"Signature generation error from {client_id}: {type(e).__name__}")
        return None
    
    if not hmac.compare_digest(signature, expected_signature):
        logger.warning(f"Cookie signature validation failed from {client_id}")
        return None
    
    return token

def validate_file_access(filename, client_id):
    if not isinstance(filename, str):
        logger.warning(f"Invalid filename type from {client_id}")
        return None
    
    if filename not in ALLOWED_FILES:
        logger.warning(f"Unauthorized file access attempt from {client_id}: {filename}")
        return None
    
    try:
        base_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
        target_path = (base_dir / filename).resolve()
    except (ValueError, OSError) as e:
        logger.error(f"Path resolution error from {client_id}: {type(e).__name__}")
        return None
    
    if not str(target_path).startswith(str(base_dir)):
        logger.warning(f"Path traversal attempt detected from {client_id}")
        return None
    
    if not target_path.is_file():
        logger.warning(f"Target is not a file from {client_id}")
        return None
    
    try:
        file_size = target_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            logger.warning(f"File size exceeds limit from {client_id}")
            return None
    except (IOError, OSError) as e:
        logger.error(f"File stat error from {client_id}: {type(e).__name__}")
        return None
    
    return target_path

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
		
		token = validate_cookie_signature(cookie_value, client_id)
		if token is None:
			return "Invalid input", 400
		
		try:
			param = urllib.parse.unquote_plus(token)
		except Exception as e:
			logger.warning(f"URL decode error from {client_id}: {type(e).__name__}")
			return "Invalid input", 400
		
		if not param or len(param) > MAX_PARAM_LENGTH or not isinstance(param, str):
			logger.warning(f"Invalid parameter received from {client_id}")
			return "Invalid input", 400

		num = 106
		
		bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

		try:
			target_path = validate_file_access(bar, client_id)
			if target_path is None:
				RESPONSE += " Invalid file path."
				return RESPONSE
			
			if not target_path.exists():
				RESPONSE += " But file doesn't exist yet."
				return RESPONSE

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

		except Exception as e:
			logger.error(f"Unexpected error from {client_id}: {type(e).__name__}")
			RESPONSE += " An error occurred."

		return RESPONSE