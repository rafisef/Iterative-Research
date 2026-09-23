from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite
import logging
import secrets
import re
import hashlib
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time

logger = logging.getLogger(__name__)

_rate_limit_store = defaultdict(list)
_rate_limit_lock = threading.Lock()
_last_cleanup = time.time()

MAX_PARAM_LENGTH = 256
PARAM_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]+$')
RATE_LIMIT_CLEANUP_INTERVAL = 3600
MAX_RATE_LIMIT_ENTRIES = 10000

def rate_limit(max_attempts=5, window_seconds=60):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			client_ip = request.remote_addr
			if not client_ip or not isinstance(client_ip, str):
				return make_response("Invalid request", 400)
			
			if len(client_ip) > 45:
				return make_response("Invalid request", 400)
			
			now = datetime.utcnow()
			
			with _rate_limit_lock:
				global _last_cleanup
				current_time = time.time()
				
				if current_time - _last_cleanup > RATE_LIMIT_CLEANUP_INTERVAL:
					old_ips = [ip for ip, timestamps in _rate_limit_store.items() if not timestamps]
					for ip in old_ips:
						del _rate_limit_store[ip]
					_last_cleanup = current_time
				
				_rate_limit_store[client_ip] = [
					ts for ts in _rate_limit_store[client_ip]
					if now - ts < timedelta(seconds=window_seconds)
				]
				
				if len(_rate_limit_store[client_ip]) >= max_attempts:
					logger.warning("Rate limit exceeded for IP: %s", client_ip)
					return make_response("Too many requests", 429)
				
				_rate_limit_store[client_ip].append(now)
				
				if len(_rate_limit_store) > MAX_RATE_LIMIT_ENTRIES:
					old_ips = sorted(
						[(ip, min(timestamps)) for ip, timestamps in _rate_limit_store.items() if timestamps],
						key=lambda x: x[1]
					)[:len(_rate_limit_store) - MAX_RATE_LIMIT_ENTRIES]
					for ip, _ in old_ips:
						del _rate_limit_store[ip]
			
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def init(app):

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		response.set_cookie('BenchmarkTest00011', secrets.token_urlsafe(32),
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	@rate_limit(max_attempts=5, window_seconds=60)
	def BenchmarkTest00011_post():
		RESPONSE = ""

		param = request.cookies.get("BenchmarkTest00011", "")
		
		if not isinstance(param, str):
			logger.warning("Invalid parameter type received from IP: %s", request.remote_addr)
			return make_response("Invalid input", 400)
		
		if len(param) == 0 or len(param) > MAX_PARAM_LENGTH:
			logger.warning("Invalid parameter length received from IP: %s", request.remote_addr)
			return make_response("Invalid input", 400)

		if not PARAM_PATTERN.match(param):
			logger.warning("Invalid characters in parameter from IP: %s", request.remote_addr)
			return make_response("Invalid input", 400)

		try:
			param_hash = hashlib.sha256(param.encode('utf-8')).hexdigest()
		except (UnicodeEncodeError, AttributeError) as e:
			logger.error("Hash computation error: %s", type(e).__name__)
			return make_response("An error occurred", 500)

		sql = 'SELECT username from USERS where password = ?'
		con = None
		try:
			con = helpers.db_sqlite.get_connection()
			if con is None:
				raise Exception("Database connection failed")
			con.isolation_level = None
			cur = con.cursor()
			cur.execute(sql, (param_hash,))
			result = helpers.db_sqlite.results(cur, sql)
			RESPONSE += escape_for_html(result) if result else ""
			cur.close()
		except Exception as e:
			logger.error("Database error occurred: %s", type(e).__name__)
			return make_response("An error occurred", 500)
		finally:
			if con is not None:
				try:
					con.close()
				except Exception as e:
					logger.error("Error closing database connection: %s", type(e).__name__)

		response = make_response(RESPONSE, 200)
		response.headers['Content-Type'] = 'text/html; charset=utf-8'
		response.headers['X-Content-Type-Options'] = 'nosniff'
		response.headers['X-Frame-Options'] = 'DENY'
		response.headers['X-XSS-Protection'] = '1; mode=block'
		response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
		response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'"
		response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
		response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
		response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
		response.headers['Pragma'] = 'no-cache'
		response.headers['Expires'] = '0'
		return response