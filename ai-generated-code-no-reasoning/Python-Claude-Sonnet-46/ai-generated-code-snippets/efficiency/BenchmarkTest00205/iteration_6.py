from flask import request
from helpers.utils import escape_for_html
from xml.etree.ElementTree import iterparse
from io import StringIO

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		param = request.form.get("BenchmarkTest00205", "")

		try:
			texts = []
			for event, elem in iterparse(StringIO(param), events=("end",)):
				if elem.text:
					texts.append(elem.text)
				if elem.tail:
					texts.append(elem.tail)
				elem.clear()
			out = "".join(texts)
			return f'Your XML doc results are: <br>{escape_for_html(out)}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'