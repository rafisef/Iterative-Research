from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
_queries = {b: f"/Employees/Employee[@emplid=\'{b}\']" for b in ("alsosafe", "moresafe")}
_nodes = {b: elementpath.select(root, q) for b, q in _queries.items()}
_responses = {}
for b, nodes in _nodes.items():
    node_strings = [' '.join([e.text for e in node]) for node in nodes]
    _responses[b] = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'

def init(app):

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie('BenchmarkTest00013', '2222',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
		bar = "moresafe" if param else "alsosafe"
		return _responses.get(bar, "")