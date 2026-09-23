from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import logging
import urllib.parse
import base64
import json
from functools import wraps
import secrets
import hashlib
import hmac
import os
from datetime import datetime, timedelta
from threading import Lock
import re
from collections import defaultdict

logger = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 10000
MAX_COOKIE_SIZE = 4096
MAX_PARAM_LENGTH = 1000
COOKIE_SIGNATURE_KEY = os.environ.get('COOKIE_SIGNATURE_KEY')
if not COOKIE_SIGNATURE_KEY:
	raise ValueError("COOKIE_SIGNATURE_KEY environment variable must be set")
if isinstance(COOKIE_SIGNATURE_KEY, str):
	COOKIE_SIGNATURE_KEY = COOKIE_SIGNATURE_KEY.encode()
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300
MAX_RATE_LIMIT_ENTRIES = 10000
RATE_LIMIT_CLEANUP_INTERVAL = 60
COOKIE_TIMEOUT = 3600

rate_limit_store = defaultdict(lambda: {'count': 0, 'timestamp': datetime.now()})
rate_limit_lock = Lock()
last_cleanup_time = datetime.now()

def cleanup_rate_limit():
	global last_cleanup_time
	current_time = datetime.now()
	
	if current_time - last_cleanup_time < timedelta(seconds=RATE_LIMIT_CLEANUP_INTERVAL):
		return
	
	expired_keys = [
		key for key, data in rate_limit_store.items()
		if current_time - data['timestamp'] > timedelta(seconds=RATE_LIMIT_WINDOW)
	]
	for key in expired_keys:
		del rate_limit_store[key]
	
	if len(rate_limit_store) > MAX_RATE_LIMIT_ENTRIES:
		oldest_key = min(rate_limit_store.keys(), key=lambda k: rate_limit_store[k]['timestamp'])
		del rate_limit_store[oldest_key]
	
	last_cleanup_time = current_time

def check_rate_limit(identifier):
	with rate_limit_lock:
		cleanup_rate_limit()
		
		current_time = datetime.now()
		
		if identifier not in rate_limit_store:
			rate_limit_store[identifier] = {'count': 1, 'timestamp': current_time}
			return True
		
		data = rate_limit_store[identifier]
		if current_time - data['timestamp'] > timedelta(seconds=RATE_LIMIT_WINDOW):
			rate_limit_store[identifier] = {'count': 1, 'timestamp': current_time}
			return True
		
		if data['count'] >= RATE_LIMIT_ATTEMPTS:
			return False
		
		data['count'] += 1
		return True

def validate_cookie_size(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		cookie_value = request.cookies.get("BenchmarkTest00078", "")
		if len(cookie_value) > MAX_COOKIE_SIZE:
			logger.warning("Cookie size exceeds limit from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400
		
		if not check_rate_limit(request.remote_addr):
			logger.warning("Rate limit exceeded from %s", request.remote_addr)
			return escape_for_html("Too many requests"), 429
		
		return f(*args, **kwargs)
	return decorated_function

def validate_cookie_signature(cookie_value):
	if not cookie_value or '.' not in cookie_value:
		return False
	
	try:
		data, signature = cookie_value.rsplit('.', 1)
		if not data or not signature:
			return False
		if len(signature) != 64:
			return False
		if not isinstance(data, str) or not isinstance(signature, str):
			return False
		if not re.match(r'^[A-Za-z0-9+/\-_=]*$', data):
			return False
		if not re.match(r'^[a-f0-9]{64}$', signature):
			return False
		
		expected_signature = hmac.new(
			COOKIE_SIGNATURE_KEY,
			data.encode('utf-8'),
			hashlib.sha256
		).hexdigest()
		return hmac.compare_digest(signature, expected_signature)
	except Exception:
		return False

def generate_secure_cookie(data):
	data_encoded = urllib.parse.quote_plus(data)
	signature = hmac.new(
		COOKIE_SIGNATURE_KEY,
		data_encoded.encode('utf-8'),
		hashlib.sha256
	).hexdigest()
	return f"{data_encoded}.{signature}"

def init(app):

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
	def BenchmarkTest00078_get():
		response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
		response.set_cookie('BenchmarkTest00078', '',
			max_age=0,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
	@validate_cookie_size
	def BenchmarkTest00078_post():
		RESPONSE = ""

		cookie_value = request.cookies.get("BenchmarkTest00078", "")
		
		if not cookie_value:
			logger.warning("Missing cookie from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400

		if not validate_cookie_signature(cookie_value):
			logger.warning("Invalid cookie signature from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400

		try:
			data_part = cookie_value.rsplit('.', 1)[0]
			if not data_part:
				logger.warning("Empty data part in cookie from %s", request.remote_addr)
				return escape_for_html("Invalid input"), 400
			param = urllib.parse.unquote_plus(data_part)
		except Exception as e:
			logger.error("Cookie parsing failed: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("Invalid input"), 400

		if not param or not isinstance(param, str) or len(param) > MAX_PARAM_LENGTH:
			logger.warning("Empty, invalid, or oversized cookie value from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400

		string9895 = 'help'
		string9895 += param
		string9895 += 'snapes on a plane'
		
		if len(string9895) < 21:
			logger.warning("Payload construction failed from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400
			
		bar = string9895[4:-17]

		if not bar:
			logger.warning("Extracted payload is empty from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400

		if len(bar) > MAX_PARAM_LENGTH:
			logger.warning("Extracted payload exceeds length from %s", request.remote_addr)
			return escape_for_html("Invalid input"), 400

		try:
			if len(bar) % 4 != 0:
				bar += '=' * (4 - len(bar) % 4)
			
			decoded = base64.urlsafe_b64decode(bar)
			if len(decoded) > MAX_PAYLOAD_SIZE:
				logger.warning("Decoded payload exceeds size limit from %s", request.remote_addr)
				return escape_for_html("Payload too large"), 413

			decoded_str = decoded.decode('utf-8', errors='strict')
			unpickled = json.loads(decoded_str, strict=True)
			
			if not isinstance(unpickled, dict):
				logger.warning("Deserialized object is not a dictionary from %s", request.remote_addr)
				return escape_for_html("Invalid data format"), 400
			
			if len(str(unpickled)) > MAX_PAYLOAD_SIZE:
				logger.warning("Deserialized object exceeds size limit from %s", request.remote_addr)
				return escape_for_html("Payload too large"), 413
				
		except ValueError as e:
			logger.error("Value error during deserialization: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("Deserialization failed"), 400
		except TypeError as e:
			logger.error("Type error during deserialization: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("Deserialization failed"), 400
		except UnicodeDecodeError as e:
			logger.error("Unicode decode error: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("Invalid encoding"), 400
		except json.JSONDecodeError as e:
			logger.error("JSON decode failed: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("Invalid JSON"), 400
		except Exception as e:
			logger.error("Unexpected error: %s from %s", type(e).__name__, request.remote_addr)
			return escape_for_html("An error occurred"), 500

		shared_string = "no pickles to be seen here"
		RESPONSE += escape_for_html(f'shared string is {shared_string}')

		return RESPONSE, 200