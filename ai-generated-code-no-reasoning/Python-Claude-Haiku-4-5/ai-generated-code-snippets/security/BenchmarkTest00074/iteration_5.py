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

logger = logging.getLogger(__name__)

RATE_LIMIT_STORE = {}
MAX_REQUESTS_PER_MINUTE = 10
REQUEST_TIMEOUT = 60

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

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		client_id = request.remote_addr
		if not check_rate_limit(client_id):
			logger.warning(f"Rate limit exceeded for {client_id}")
			return escape_for_html("Too many requests"), 429
		
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
	def BenchmarkTest00074_post():
		client_id = request.remote_addr
		if not check_rate_limit(client_id):
			logger.warning(f"Rate limit exceeded for {client_id}")
			return escape_for_html("Too many requests"), 429
		
		RESPONSE = ""

		csrf_token = request.cookies.get("csrf_token")
		stored_hash = request.cookies.get("BenchmarkTest00074")
		
		if not csrf_token or not stored_hash:
			logger.warning(f"Missing CSRF protection tokens from {client_id}")
			return escape_for_html("Invalid request"), 400
		
		if hashlib.sha256(csrf_token.encode()).hexdigest() != stored_hash:
			logger.warning(f"CSRF token validation failed from {client_id}")
			return escape_for_html("Invalid request"), 403

		param = urllib.parse.unquote_plus(request.form.get("param", "noCookieValueSupplied"))
		
		if not isinstance(param, str) or len(param) > 100:
			logger.warning(f"Invalid parameter received from {client_id}")
			return escape_for_html("Invalid input"), 400
		
		if not re.match(r'^[a-zA-Z0-9\s\t\n\+\-\*\/\(\)\.]*$', param):
			logger.warning(f"Invalid parameter format from {client_id}")
			return escape_for_html("Invalid input"), 400
		
		bar = 'safe!'
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			tree = ast.parse(bar)
			
			disallowed_nodes = (
				ast.Import, ast.ImportFrom, ast.Call, ast.Attribute,
				ast.Subscript, ast.Delete, ast.Assert, ast.Raise,
				ast.Try, ast.With, ast.FunctionDef, ast.AsyncFunctionDef,
				ast.ClassDef, ast.Lambda, ast.Exec, ast.Global,
				ast.Nonlocal, ast.Return, ast.Yield, ast.YieldFrom
			)
			
			for node in ast.walk(tree):
				if isinstance(node, disallowed_nodes):
					logger.error(f"Disallowed operation detected from {client_id}")
					return escape_for_html("Invalid operation"), 400
			
			restricted_globals = {
				'__builtins__': {},
				'__name__': '__main__',
				'__doc__': None
			}
			restricted_locals = {}
			
			exec(bar, restricted_globals, restricted_locals)
		except SyntaxError as e:
			logger.error(f"Invalid syntax in parameter from {client_id}")
			RESPONSE += escape_for_html("Invalid syntax")
		except Exception as e:
			logger.error(f"Execution error from {client_id}: {type(e).__name__}")
			RESPONSE += escape_for_html("Error executing statement")

		return RESPONSE, 200