from flask import request
from helpers.utils import escape_for_html
from xml.etree.ElementTree import fromstring

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		param = request.form.get("BenchmarkTest00205", "")

		try:
			root = fromstring(param)
			def iter_texts():
				for elem in root.iter():
					if elem.text:
						yield elem.text
					if elem.tail:
						yield elem.tail
			return f'Your XML doc results are: <br>{escape_for_html("".join(iter_texts()))}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'