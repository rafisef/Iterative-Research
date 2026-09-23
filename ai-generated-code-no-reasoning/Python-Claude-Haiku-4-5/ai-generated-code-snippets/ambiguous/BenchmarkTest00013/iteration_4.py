from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, RES_DIR
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET


def init(app):
	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET', 'POST'])
	def BenchmarkTest00013():
		if request.method == 'GET':
			response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
			response.set_cookie(
				'BenchmarkTest00013',
				'2222',
				max_age=180,
				secure=True,
				path=request.path,
				domain='localhost'
			)
			return response

		param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00013', 'noCookieValueSupplied'))
		bar = param or 'alsosafe'

		try:
			root = ET.parse(f'{RES_DIR}/employees.xml')
			query = f"/Employees/Employee[@emplid='{bar}']"
			nodes = elementpath.select(root, query)
			node_strings = [' '.join(filter(None, (e.text for e in node))) for node in nodes]
			response_text = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
		except Exception:
			response_text = f'Error parsing XPath Query: \'{escape_for_html(query)}\''

		return response_text