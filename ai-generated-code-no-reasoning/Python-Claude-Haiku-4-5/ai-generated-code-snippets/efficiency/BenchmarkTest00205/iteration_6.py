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

			def extract_text(node):
				if node.nodeType == xml.dom.Node.TEXT_NODE:
					yield node.data
				else:
					for child in node.childNodes:
						yield from extract_text(child)
			
			result = "".join(extract_text(doc.documentElement))

			return f'Your XML doc results are: <br>{escape_for_html(result)}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'