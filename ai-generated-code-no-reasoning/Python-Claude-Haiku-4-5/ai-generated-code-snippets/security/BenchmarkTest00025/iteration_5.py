import secrets
import string
import hashlib
import hmac
from urllib.parse import unquote_plus
from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import os
import logging
from functools import wraps
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

MAX_COOKIE_SIZE = 256
MAX_SESSION_AGE = 86400
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300

def init(app):
	secret_key = os.environ.get('SECRET_KEY')
	if not secret_key:
		logger.error('SECRET_KEY not set in environment')
		raise ValueError('SECRET_KEY environment variable must be set')
	
	if len(secret_key) < 32:
		logger.error('SECRET_KEY must be at least 32 characters')
		raise ValueError('SECRET_KEY must be at least 32 characters')
	
	app.config['SECRET_KEY'] = secret_key
	app.config['SESSION_COOKIE_SECURE'] = True
	app.config['SESSION_COOKIE_HTTPONLY'] = True
	app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
	app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		secure_token = secrets.token_urlsafe(32)
		response.set_cookie('BenchmarkTest00025', secure_token,
			max_age=180,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		try:
			param = unquote_plus(request.cookies.get("BenchmarkTest00025", ""))
			
			if not param:
				return escape("Invalid input"), 400
			
			if not isinstance(param, str) or len(param) > MAX_COOKIE_SIZE:
				return escape("Invalid input"), 400

			if not param.isascii():
				return escape("Invalid input"), 400

			superstring = f'90583{param}abcd'
			bar = superstring[len('90583'):len(superstring)-5]

			from helpers.utils import mysession

			num = '00025'
			user = f'Nancy{num}'
			cookie = f'rememberMe{num}'
			value = secrets.token_urlsafe(32)

			secret_key = app.config.get('SECRET_KEY', '').encode()
			
			if not secret_key or len(secret_key) < 32:
				logger.error('SECRET_KEY not properly configured')
				return escape("Configuration error"), 500
			
			stored_cookie = mysession.get(cookie, '')
			if stored_cookie:
				cookie_hash = hmac.new(secret_key, stored_cookie.encode(), hashlib.sha256).digest()
			else:
				cookie_hash = b''
			
			request_cookie = request.cookies.get(cookie, '')
			if request_cookie:
				request_hash = hmac.new(secret_key, request_cookie.encode(), hashlib.sha256).digest()
			else:
				request_hash = b''

			if cookie in mysession and hmac.compare_digest(request_hash, cookie_hash) and stored_cookie:
				RESPONSE = escape(f'Welcome back: {user}<br/>')
			else:
				mysession[cookie] = value
				RESPONSE = escape(f'{user} has been remembered<br/>')

			response = make_response(RESPONSE)
			response.set_cookie(cookie, value,
				max_age=MAX_SESSION_AGE,
				secure=True,
				httponly=True,
				samesite='Strict',
				path='/',
				domain=None)
			return response
		
		except Exception as e:
			logger.error(f'Unexpected error in BenchmarkTest00025_post: {str(e)}')
			return escape("An error occurred"), 500