from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
from typing import Optional
import os
from pathlib import Path
import logging
import hashlib
import hmac
import secrets
import re
from markupsafe import Markup
import time
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logger = logging.getLogger(__name__)

COOKIE_NAME = 'BenchmarkTest00013'
COOKIE_TIMEOUT = 60 * 3
COOKIE_SECRET = os.environ.get('COOKIE_SECRET')
if not COOKIE_SECRET:
	raise ValueError("COOKIE_SECRET environment variable must be set")
MAX_INPUT_LENGTH = 32
VALID_PATTERN = r'^[a-zA-Z0-9_\-]{1,32}$'
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10

def validate_cookie_signature(cookie_value: str, signature: str) -> bool:
	expected_sig = hmac.new(
		COOKIE_SECRET.encode(),
		cookie_value.encode(),
		hashlib.sha256
	).hexdigest()
	return hmac.compare_digest(expected_sig, signature)

def create_signed_cookie_value() -> tuple:
	value = secrets.token_urlsafe(16)
	signature = hmac.new(
		COOKIE_SECRET.encode(),
		value.encode(),
		hashlib.sha256
	).hexdigest()
	return f"{value}.{signature}", value

def init(app):
	limiter = Limiter(
		app=app,
		key_func=get_remote_address,
		default_limits=["200 per day", "50 per hour"]
	)

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	@limiter.limit("10 per minute")
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		cookie_value, _ = create_signed_cookie_value()
		response.set_cookie(
			COOKIE_NAME,
			cookie_value,
			max_age=COOKIE_TIMEOUT,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None
		)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	@limiter.limit("10 per minute")
	def BenchmarkTest00013_post():
		RESPONSE = ""

		cookie_value = request.cookies.get(COOKIE_NAME, "")
		
		if not cookie_value or '.' not in cookie_value:
			return escape("Invalid request"), 400
		
		try:
			value, signature = cookie_value.rsplit('.', 1)
			if not validate_cookie_signature(value, signature):
				return escape("Invalid request"), 400
		except (ValueError, IndexError):
			return escape("Invalid request"), 400

		param = urllib.parse.unquote_plus(value)

		if not isinstance(param, str) or len(param) > MAX_INPUT_LENGTH:
			return escape("Invalid input"), 400

		if not re.match(VALID_PATTERN, param):
			return escape("Invalid input format"), 400

		bar = param if param and param != value else "alsosafe"

		if not re.match(VALID_PATTERN, bar):
			return escape("Invalid characters in parameter"), 400

		try:
			xml_path = Path(helpers.utils.RES_DIR).resolve() / 'employees.xml'
			base_path = Path(helpers.utils.RES_DIR).resolve()
			
			if not xml_path.exists() or not xml_path.is_file():
				return escape("Resource not found"), 404

			try:
				xml_path.resolve().relative_to(base_path)
			except ValueError:
				return escape("Invalid path"), 400

			with open(str(xml_path), 'r', encoding='utf-8') as f:
				root = ET.parse(f)

			node_strings = []
			escaped_bar = re.sub(r"['\"\[\]()=<>]", "", bar)
			
			if len(escaped_bar) > 32:
				return escape("Invalid input"), 400
			
			nodes = elementpath.select(root, f"/Employees/Employee[@emplid='{escaped_bar}']")
			
			for node in nodes:
				node_text = ' '.join([str(e.text) for e in node if e.text and isinstance(e.text, str)])
				if node_text:
					node_strings.append(escape(node_text))

			safe_results = ", ".join(node_strings[:100])
			RESPONSE = Markup(f'Your XPATH query results are: <br>[ {safe_results} ]')
			
		except ET.ParseError:
			logger.warning("XML parsing error")
			RESPONSE = escape('Error parsing XML document')
		except Exception as e:
			logger.error("XPath query error")
			RESPONSE = escape('Error processing XPath query')

		return RESPONSE