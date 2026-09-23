from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import configparser
import logging
import ast
import re
import hashlib
import secrets

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
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
	def BenchmarkTest00074_post():
		RESPONSE = ""

		csrf_token = request.cookies.get("csrf_token")
		stored_hash = request.cookies.get("BenchmarkTest00074")
		
		if not csrf_token or not stored_hash:
			logger.warning("Missing CSRF protection tokens")
			return escape_for_html("Invalid request")
		
		if hashlib.sha256(csrf_token.encode()).hexdigest() != stored_hash:
			logger.warning("CSRF token validation failed")
			return escape_for_html("Invalid request")

		param = urllib.parse.unquote_plus(request.form.get("param", "noCookieValueSupplied"))
		
		if not isinstance(param, str) or len(param) > 100:
			logger.warning("Invalid parameter received")
			return escape_for_html("Invalid input")
		
		if not re.match(r'^[a-zA-Z0-9\s\t\n\+\-\*\/\(\)]*$', param):
			logger.warning("Invalid parameter format")
			return escape_for_html("Invalid input")
		
		bar = 'safe!'
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			tree = ast.parse(bar)
			
			for node in ast.walk(tree):
				if isinstance(node, (ast.Import, ast.ImportFrom, ast.Call, ast.Attribute)):
					logger.error("Disallowed operation detected")
					return escape_for_html("Invalid operation")
			
			allowed_names = {
				'__builtins__': {}
			}
			restricted_globals = {
				'__builtins__': {},
				'__name__': '__main__',
				'__doc__': None
			}
			
			exec(bar, restricted_globals, allowed_names)
		except SyntaxError:
			logger.error("Invalid syntax in parameter")
			RESPONSE += escape_for_html("Invalid syntax")
		except Exception as e:
			logger.error(f"Execution error: {type(e).__name__}")
			RESPONSE += escape_for_html(f'Error executing statement')

		return RESPONSE