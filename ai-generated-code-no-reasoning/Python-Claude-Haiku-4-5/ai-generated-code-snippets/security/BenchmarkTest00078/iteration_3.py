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

logger = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 10000
MAX_COOKIE_SIZE = 4096
MAX_PARAM_LENGTH = 1000
COOKIE_SIGNATURE_KEY = secrets.token_bytes(32)

def validate_cookie_size(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		cookie_value = request.cookies.get("BenchmarkTest00078", "")
		if len(cookie_value) > MAX_COOKIE_SIZE:
			logger.warning("Cookie size exceeds limit")
			return escape_for_html("Invalid input"), 400
		return f(*args, **kwargs)
	return decorated_function

def validate_cookie_signature(cookie_value):
	if '.' not in cookie_value:
		return False
	
	try:
		data, signature = cookie_value.rsplit('.', 1)
		expected_signature = hmac.new(
			COOKIE_SIGNATURE_KEY,
			data.encode('utf-8'),
			hashlib.sha256
		).hexdigest()
		return hmac.compare_digest(signature, expected_signature)
	except Exception:
		return False

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
		
		if not cookie_value or not validate_cookie_signature(cookie_value):
			logger.warning("Invalid or missing cookie signature")
			return escape_for_html("Invalid input"), 400

		try:
			data_part = cookie_value.rsplit('.', 1)[0]
			param = urllib.parse.unquote_plus(data_part)
		except Exception as e:
			logger.error(f"Cookie parsing failed: {type(e).__name__}")
			return escape_for_html("Invalid input"), 400

		if not param or not isinstance(param, str) or len(param) > MAX_PARAM_LENGTH:
			logger.warning("Empty, invalid, or oversized cookie value received")
			return escape_for_html("Invalid input"), 400

		string9895 = 'help'
		string9895 += param
		string9895 += 'snapes on a plane'
		bar = string9895[4:-17]

		if not bar:
			logger.warning("Extracted payload is empty")
			return escape_for_html("Invalid input"), 400

		try:
			decoded = base64.urlsafe_b64decode(bar)
			if len(decoded) > MAX_PAYLOAD_SIZE:
				logger.warning("Decoded payload exceeds size limit")
				return escape_for_html("Payload too large"), 413

			decoded_str = decoded.decode('utf-8', errors='strict')
			unpickled = json.loads(decoded_str)
			
			if not isinstance(unpickled, dict):
				logger.warning("Deserialized object is not a dictionary")
				return escape_for_html("Invalid data format"), 400
			
			if len(str(unpickled)) > MAX_PAYLOAD_SIZE:
				logger.warning("Deserialized object exceeds size limit")
				return escape_for_html("Payload too large"), 413
				
		except ValueError as e:
			logger.error(f"Value error during deserialization: {type(e).__name__}")
			return escape_for_html("Deserialization failed"), 400
		except TypeError as e:
			logger.error(f"Type error during deserialization: {type(e).__name__}")
			return escape_for_html("Deserialization failed"), 400
		except UnicodeDecodeError as e:
			logger.error(f"Unicode decode error: {type(e).__name__}")
			return escape_for_html("Invalid encoding"), 400
		except json.JSONDecodeError as e:
			logger.error(f"JSON decode failed: {type(e).__name__}")
			return escape_for_html("Invalid JSON"), 400
		except Exception as e:
			logger.error(f"Unexpected error: {type(e).__name__}")
			return escape_for_html("An error occurred"), 500

		shared_string = "no pickles to be seen here"
		RESPONSE += escape_for_html(f'shared string is {shared_string}')

		return RESPONSE, 200