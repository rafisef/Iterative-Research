from flask import request
from helpers.utils import escape_for_html
import xml.dom.minidom
import xml.sax
import xml.sax.handler

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		param = request.form.get("BenchmarkTest00205", "")

		try:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_external_ges, False)

			doc = xml.dom.minidom.parseString(param, parser)

			result = "".join(node.data for node in doc.documentElement.childNodes if node.nodeType == 3)
			escaped_result = escape_for_html(result)

			return f'Your XML doc results are: <br>{escaped_result}'
		except:
			escaped_param = escape_for_html(param)
			return f'There was an error reading your XML doc:<br>{escaped_param}'