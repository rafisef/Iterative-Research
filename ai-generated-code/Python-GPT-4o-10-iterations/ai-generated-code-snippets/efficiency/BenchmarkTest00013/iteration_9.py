from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, RES_DIR
import elementpath
import xml.etree.ElementTree as ET

def init(app):

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie('BenchmarkTest00013', '2222',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		bar = request.cookies.get("BenchmarkTest00013", "alsosafe")

		try:
			query = f"/Employees/Employee[@emplid='{bar}']"
			tree = ET.parse(f'{RES_DIR}/employees.xml')
			nodes = elementpath.select(tree, query)
			node_strings = [' '.join(node.itertext()) for node in nodes]

			RESPONSE = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
		except Exception:
			RESPONSE = f'Error parsing XPath Query: \'{escape_for_html(query)}\''

		return RESPONSE