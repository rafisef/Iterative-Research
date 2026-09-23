from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import configparser
import logging
import ast
import re
import hashlib
import secrets
import time
from functools import wraps
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests

logger = logging.getLogger(__name__)

RATE_LIMIT_STORE = {}
MAX_REQUESTS_PER_MINUTE = 10
REQUEST_TIMEOUT = 60
MAX_PARAM_LENGTH = 100

def check_rate_limit(client_id):
	current_time = time.time()
	if client_id not in RATE_LIMIT_STORE:
		RATE_LIMIT_STORE[client_id] = []
	
	RATE_LIMIT_STORE[client_id] = [
		timestamp for timestamp in RATE_LIMIT_STORE[client_id]
		if current_time - timestamp < REQUEST_TIMEOUT
	]
	
	if len(RATE_LIMIT_STORE[client_id]) >= MAX_REQUESTS_PER_MINUTE:
		return False
	
	RATE_LIMIT_STORE[client_id].append(current_time)
	return True

def rate_limit_decorator(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		client_id = request.remote_addr or "unknown"
		if not check_rate_limit(client_id):
			logger.warning(f"Rate limit exceeded for {client_id}")
			raise TooManyRequests("Too many requests")
		return f(*args, **kwargs)
	return decorated_function

def verify_csrf(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		client_id = request.remote_addr or "unknown"
		csrf_token = request.cookies.get("csrf_token")
		stored_hash = request.cookies.get("BenchmarkTest00074")
		
		if not csrf_token or not stored_hash:
			logger.warning(f"Missing CSRF protection tokens from {client_id}")
			raise BadRequest("Invalid request")
		
		if not isinstance(csrf_token, str) or len(csrf_token) > 256:
			logger.warning(f"Invalid CSRF token format from {client_id}")
			raise BadRequest("Invalid request")
		
		try:
			token_hash = hashlib.sha256(csrf_token.encode()).hexdigest()
		except Exception as e:
			logger.error(f"CSRF token hashing failed from {client_id}")
			raise BadRequest("Invalid request")
		
		if token_hash != stored_hash:
			logger.warning(f"CSRF token validation failed from {client_id}")
			raise Forbidden("Invalid request")
		
		return f(*args, **kwargs)
	return decorated_function

def validate_param(param):
	if not isinstance(param, str):
		raise BadRequest("Invalid input")
	
	if len(param) == 0 or len(param) > MAX_PARAM_LENGTH:
		raise BadRequest("Invalid input")
	
	if not re.match(r'^[a-zA-Z0-9\s\t\n\+\-\*\/\(\)\.]*$', param):
		raise BadRequest("Invalid input")
	
	return param

def is_safe_ast(tree):
	disallowed_nodes = (
		ast.Import, ast.ImportFrom, ast.Call, ast.Attribute,
		ast.Subscript, ast.Delete, ast.Assert, ast.Raise,
		ast.Try, ast.With, ast.FunctionDef, ast.AsyncFunctionDef,
		ast.ClassDef, ast.Lambda, ast.Global,
		ast.Nonlocal, ast.Return, ast.Yield, ast.YieldFrom
	)
	
	for node in ast.walk(tree):
		if isinstance(node, disallowed_nodes):
			return False
	
	return True

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	@rate_limit_decorator
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		csrf_token = secrets.token_urlsafe(32)
		response.set_cookie('csrf_token', csrf_token,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		response.set_cookie('BenchmarkTest00074', hashlib.sha256(csrf_token.encode()).hexdigest(),
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	@rate_limit_decorator
	@verify_csrf
	def BenchmarkTest00074_post():
		client_id = request.remote_addr or "unknown"
		RESPONSE = ""

		try:
			param = urllib.parse.unquote_plus(request.form.get("param", "noCookieValueSupplied"))
			param = validate_param(param)
		except BadRequest as e:
			logger.warning(f"Invalid parameter from {client_id}: {str(e)}")
			raise

		try:
			tree = ast.parse(param)
			
			if not is_safe_ast(tree):
				logger.error(f"Disallowed operation detected from {client_id}")
				raise BadRequest("Invalid operation")
			
			restricted_globals = {
				'__builtins__': {},
				'__name__': '__main__',
				'__doc__': None
			}
			restricted_locals = {}
			
			exec(param, restricted_globals, restricted_locals)
			RESPONSE = escape_for_html("Success")
		except SyntaxError as e:
			logger.error(f"Invalid syntax in parameter from {client_id}")
			RESPONSE = escape_for_html("Invalid syntax")
		except BadRequest:
			raise
		except Exception as e:
			logger.error(f"Execution error from {client_id}: {type(e).__name__}")
			RESPONSE = escape_for_html("Error executing statement")

		return RESPONSE, 200