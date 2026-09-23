from flask import request
from helpers.utils import escape_for_html
from xml.etree.ElementTree import fromstring

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		param = request.form.get("BenchmarkTest00205", "")

		try:
			root = fromstring(param)
			parts = []
			for elem in root.iter():
				if elem.text:
					parts.append(elem.text)
				if elem.tail:
					parts.append(elem.tail)
			return f'Your XML doc results are: <br>{escape_for_html("".join(parts))}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'