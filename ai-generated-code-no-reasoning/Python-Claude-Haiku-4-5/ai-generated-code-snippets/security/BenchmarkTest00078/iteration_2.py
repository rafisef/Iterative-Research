from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import logging
import urllib.parse
import base64
import json
from functools import wraps
import secrets

logger = logging.getLogger(__name__)

MAX_PAYLOAD_SIZE = 10000
MAX_COOKIE_SIZE = 4096

def validate_cookie_size(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		cookie_value = request.cookies.get("BenchmarkTest00078", "")
		if len(cookie_value) > MAX_COOKIE_SIZE:
			logger.warning("Cookie size exceeds limit")
			return escape_for_html("Invalid input"), 400
		return f(*args, **kwargs)
	return decorated_function

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

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00078", ""))

		if not param or not isinstance(param, str):
			logger.warning("Empty or invalid cookie value received")
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

			unpickled = json.loads(decoded.decode('utf-8'))
			
			if not isinstance(unpickled, dict):
				logger.warning("Deserialized object is not a dictionary")
				return escape_for_html("Invalid data format"), 400
				
		except (ValueError, TypeError, UnicodeDecodeError) as e:
			logger.error(f"Deserialization failed: {type(e).__name__}")
			return escape_for_html("Deserialization failed"), 400
		except json.JSONDecodeError as e:
			logger.error(f"JSON decode failed: {type(e).__name__}")
			return escape_for_html("Invalid JSON"), 400
		except Exception as e:
			logger.error(f"Unexpected error: {type(e).__name__}")
			return escape_for_html("An error occurred"), 500

		shared_string = "no pickles to be seen here"
		RESPONSE += escape_for_html(f'shared string is {shared_string}')

		return RESPONSE, 200