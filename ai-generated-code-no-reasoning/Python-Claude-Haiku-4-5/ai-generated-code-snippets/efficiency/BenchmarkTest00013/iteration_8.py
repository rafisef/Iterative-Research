from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

def init(app):
	_COOKIE_NAME = 'BenchmarkTest00013'
	_COOKIE_MAX_AGE = 60 * 3
	_DEFAULT_RESPONSE = "alsosafe"
	_EMPLOYEES_PATH = f'{helpers.utils.RES_DIR}/employees.xml'
	_root = ET.parse(_EMPLOYEES_PATH)
	_template = render_template('web/xpathi-00/BenchmarkTest00013.html')
	_cached_results = {}

	def get_xpath_result(bar):
		if bar in _cached_results:
			return _cached_results[bar]
		
		try:
			query = f"/Employees/Employee[@emplid=\'{bar}\']"
			nodes = elementpath.select(_root, query)
			node_strings = [node.text for node in nodes if node.text]
			RESPONSE = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
		except:
			RESPONSE = f'Error parsing XPath Query: \'{escape_for_html(query)}\''

		_cached_results[bar] = RESPONSE
		return RESPONSE

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(_template)
		response.set_cookie(_COOKIE_NAME, '2222',
			max_age=_COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
		bar = param or _DEFAULT_RESPONSE
		return get_xpath_result(bar)