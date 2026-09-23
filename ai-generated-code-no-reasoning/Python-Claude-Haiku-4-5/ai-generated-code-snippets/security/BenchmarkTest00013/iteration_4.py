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

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie('BenchmarkTest00013', '2222',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain='localhost')
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))

		if not isinstance(param, str) or len(param) > 100:
			return escape("Invalid input")

		if not param.replace('_', '').replace('-', '').isalnum():
			return escape("Invalid input format")

		bar = "alsosafe"
		if param and param != "noCookieValueSupplied":
			lst = []
			lst.append('safe')
			lst.append(param)
			lst.append('moresafe')
			lst.pop(0)
			bar = lst[1]

		try:
			xml_path = Path(helpers.utils.RES_DIR).resolve() / 'employees.xml'
			base_path = Path(helpers.utils.RES_DIR).resolve()
			
			if not xml_path.exists() or not xml_path.is_file():
				return escape("Resource not found")

			if not xml_path.resolve().is_relative_to(base_path):
				return escape("Invalid path")

			with open(str(xml_path), 'r', encoding='utf-8') as f:
				root = ET.parse(f)

			safe_bar = escape(bar).replace("'", "&apos;").replace('"', "&quot;")
			query = f"/Employees/Employee[@emplid='{safe_bar}']"

			nodes = elementpath.select(root, query)
			node_strings = []
			for node in nodes:
				node_text = ' '.join([e.text for e in node if e.text and isinstance(e.text, str)])
				if node_text:
					node_strings.append(escape(node_text))

			RESPONSE += (
				f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
			)
		except ET.ParseError:
			logger.warning("XML parsing error")
			RESPONSE += escape('Error parsing XML document')
		except Exception as e:
			logger.error("XPath query error")
			RESPONSE += escape('Error processing XPath query')

		return RESPONSE