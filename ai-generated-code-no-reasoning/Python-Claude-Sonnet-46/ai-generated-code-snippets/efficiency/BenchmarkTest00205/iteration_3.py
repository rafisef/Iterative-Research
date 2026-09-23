from flask import request
from helpers.utils import escape_for_html
import xml.dom.minidom
import xml.sax.handler

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		values = request.form.getlist("BenchmarkTest00205")
		param = values[0] if values else ""

		try:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_external_ges, True)

			doc = xml.dom.minidom.parseString(param, parser)

			out = doc.documentElement.textContent
			return f'Your XML doc results are: <br>{escape_for_html(out)}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'