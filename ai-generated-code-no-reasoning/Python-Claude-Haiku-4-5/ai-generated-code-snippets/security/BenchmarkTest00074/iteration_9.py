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
from collections import defaultdict
from threading import Lock
import ipaddress

logger = logging.getLogger(__name__)

RATE_LIMIT_STORE = defaultdict(list)
RATE_LIMIT_LOCK = Lock()
MAX_REQUESTS_PER_MINUTE = 10
REQUEST_TIMEOUT = 60
MAX_PARAM_LENGTH = 100
CSRF_TOKEN_LENGTH = 32
MAX_CSRF_TOKEN_LENGTH = 256
MAX_CLIENT_ID_LENGTH = 50
MAX_FORWARDED_FOR_LENGTH = 1000

def get_client_identifier():
	client_id = request.remote_addr
	if not client_id:
		forwarded_for = request.headers.get('X-Forwarded-For', '')
		if forwarded_for and len(forwarded_for) <= MAX_FORWARDED_FOR_LENGTH:
			try:
				client_id = forwarded_for.split(',')[0].strip()
				ipaddress.ip_address(client_id)
			except (ValueError, IndexError):
				client_id = 'unknown'
		else:
			client_id = 'unknown'
	
	if not client_id:
		client_id = 'unknown'
	
	try:
		ipaddress.ip_address(client_id)
	except ValueError:
		client_id = 'unknown'
	
	return client_id[:MAX_CLIENT_ID_LENGTH]

def check_rate_limit(client_id):
	current_time = time.time()
	with RATE_LIMIT_LOCK:
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
		client_id = get_client_identifier()
		if not check_rate_limit(client_id):
			logger.warning(f"Rate limit exceeded for {escape_for_html(client_id)}")
			raise TooManyRequests("Too many requests")
		return f(*args, **kwargs)
	return decorated_function

def verify_csrf(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		client_id = get_client_identifier()
		csrf_token = request.form.get("csrf_token")
		stored_hash = request.cookies.get("BenchmarkTest00074")
		
		if not csrf_token or not stored_hash:
			logger.warning(f"Missing CSRF protection tokens from {escape_for_html(client_id)}")
			raise BadRequest("Invalid request")
		
		if not isinstance(csrf_token, str) or len(csrf_token) > MAX_CSRF_TOKEN_LENGTH or len(csrf_token) < 20:
			logger.warning(f"Invalid CSRF token format from {escape_for_html(client_id)}")
			raise BadRequest("Invalid request")
		
		if not isinstance(stored_hash, str) or len(stored_hash) != 64:
			logger.warning(f"Invalid stored hash format from {escape_for_html(client_id)}")
			raise BadRequest("Invalid request")
		
		if not re.match(r'^[a-f0-9]{64}$', stored_hash):
			logger.warning(f"Invalid stored hash format from {escape_for_html(client_id)}")
			raise BadRequest("Invalid request")
		
		try:
			token_hash = hashlib.sha256(csrf_token.encode('utf-8')).hexdigest()
		except Exception as e:
			logger.error(f"CSRF token hashing failed from {escape_for_html(client_id)}")
			raise BadRequest("Invalid request")
		
		if not secrets.compare_digest(token_hash, stored_hash):
			logger.warning(f"CSRF token validation failed from {escape_for_html(client_id)}")
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
		ast.Nonlocal, ast.Return, ast.Yield, ast.YieldFrom,
		ast.Exec, ast.Eval, ast.Compile
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
		csrf_token = secrets.token_urlsafe(CSRF_TOKEN_LENGTH)
		response.set_cookie('csrf_token', csrf_token,
			max_age=180,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		response.set_cookie('BenchmarkTest00074', hashlib.sha256(csrf_token.encode('utf-8')).hexdigest(),
			max_age=180,
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
		client_id = get_client_identifier()
		RESPONSE = ""

		try:
			param = urllib.parse.unquote_plus(request.form.get("param", "noCookieValueSupplied"))
			param = validate_param(param)
		except BadRequest as e:
			logger.warning(f"Invalid parameter from {escape_for_html(client_id)}")
			raise

		try:
			tree = ast.parse(param)
			
			if not is_safe_ast(tree):
				logger.error(f"Disallowed operation detected from {escape_for_html(client_id)}")
				raise BadRequest("Invalid operation")
			
			restricted_globals = {
				'__builtins__': {},
				'__name__': '__main__',
				'__doc__': None
			}
			restricted_locals = {}
			
			compile(param, '<string>', 'exec')
			RESPONSE = escape_for_html("Success")
		except SyntaxError as e:
			logger.error(f"Invalid syntax in parameter from {escape_for_html(client_id)}")
			RESPONSE = escape_for_html("Invalid syntax")
		except BadRequest:
			raise
		except Exception as e:
			logger.error(f"Execution error from {escape_for_html(client_id)}: {type(e).__name__}")
			RESPONSE = escape_for_html("Error executing statement")

		return RESPONSE, 200