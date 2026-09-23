from flask import request
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		param = request.form.get("BenchmarkTest00205", "")

		try:
			root = ET.fromstring(param)
			out = "".join(root.itertext())
			return f'Your XML doc results are: <br>{escape_for_html(out)}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'