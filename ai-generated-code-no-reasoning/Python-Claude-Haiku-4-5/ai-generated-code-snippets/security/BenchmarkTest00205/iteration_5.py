from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET
import configparser
import logging
import re
import hashlib
import secrets
from markupsafe import Markup

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
	def BenchmarkTest00205_get():
		return BenchmarkTest00205_post()

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
	def BenchmarkTest00205_post():
		RESPONSE = ""

		values = request.form.getlist("BenchmarkTest00205")
		param = ""
		if values:
			param = values[0]

		if not isinstance(param, str) or len(param) > 10000:
			RESPONSE += "Invalid input"
			return RESPONSE, 400, {'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'CSP': "default-src 'none'"}

		if not re.match(r'^[a-zA-Z0-9<>/=\s\-._:]*$', param):
			RESPONSE += "Invalid characters in input"
			return RESPONSE, 400, {'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'CSP': "default-src 'none'"}

		try:
			param_bytes = param.encode('utf-8')
			if len(param_bytes) > 10000:
				RESPONSE += "Input too large"
				return RESPONSE, 400, {'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'CSP': "default-src 'none'"}
		except UnicodeEncodeError:
			RESPONSE += "Invalid encoding"
			return RESPONSE, 400, {'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'CSP': "default-src 'none'"}

		bar = 'safe!'
		conf60568 = configparser.ConfigParser()
		conf60568.add_section('section60568')
		conf60568.set('section60568', 'keyA-60568', 'a-Value')
		conf60568.set('section60568', 'keyB-60568', param)
		bar = conf60568.get('section60568', 'keyB-60568')

		try:
			doc = DefusedET.fromstring(
				bar,
				forbid_dtd=True,
				forbid_entities=True,
				forbid_external=True
			)

			out = ''
			processing = [doc]
			max_depth = 100
			current_depth = 0
			max_elements = 1000
			element_count = 0
			
			while processing and current_depth < max_depth and element_count < max_elements:
				e = processing.pop(0)
				if e.text and len(e.text) > 0:
					text_content = escape_for_html(e.text)
					if len(out) + len(text_content) > 50000:
						break
					out += text_content
				processing[:0] = list(e)
				current_depth += 1
				element_count += 1

			RESPONSE += (
				f'Your XML doc results are: <br>{escape_for_html(out)}'
			)
		except Exception as e:
			logger.warning(f"XML parsing error: {type(e).__name__}", exc_info=False)
			RESPONSE += (
				f'There was an error reading your XML doc'
			)

		return RESPONSE, 200, {'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'", 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'}