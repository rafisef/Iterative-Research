from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import html
import re
from markupsafe import Markup
from werkzeug.security import safe_str_cmp
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
	def BenchmarkTest00096_get():
		return BenchmarkTest00096_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
	def BenchmarkTest00096_post():
		RESPONSE = ""

		param = request.form.get("BenchmarkTest00096", "")
		
		if param:
			if not isinstance(param, str):
				param = str(param)
			
			param = param.strip()
			
			if len(param) > 1000:
				param = param[:1000]
			
			if not re.match(r'^[a-zA-Z0-9\s\-_.]*$', param):
				logger.warning(f"Invalid parameter format detected: potential attack attempt")
				param = ""
		
		param_escaped = html.escape(param, quote=True)
		
		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = param_escaped
			case 'B':
				bar = 'bob'
			case 'C' | 'D':
				bar = param_escaped
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		bar_escaped = html.escape(str(bar), quote=True)
		otherarg_escaped = html.escape(str(otherarg), quote=True)
		
		RESPONSE += (
			f'bar is \'{bar_escaped}\' and otherarg is \'{otherarg_escaped}\''
		)

		response = make_response(RESPONSE)
		response.headers['Content-Type'] = 'text/html; charset=utf-8'
		response.headers['X-Content-Type-Options'] = 'nosniff'
		response.headers['X-Frame-Options'] = 'DENY'
		response.headers['X-XSS-Protection'] = '1; mode=block'
		
		expires = datetime.utcnow() + timedelta(days=365)
		response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
		response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
		response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
		response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
		response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
		response.headers['Pragma'] = 'no-cache'
		response.headers['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
		response.headers['Set-Cookie'] = 'HttpOnly; Secure; SameSite=Strict'
		
		return response