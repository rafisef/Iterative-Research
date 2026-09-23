from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET
import configparser
import logging

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
	def BenchmarkTest00205_get():
		return BenchmarkTest00205_post()

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
	def BenchmarkTest00205_post():
		RESPONSE = ""

		values = request.form.getlist("BenchmarkTest00205")
		param = ""
		if values:
			param = values[0]

		if not isinstance(param, str) or len(param) > 10000:
			RESPONSE += "Invalid input"
			return RESPONSE

		bar = 'safe!'
		conf60568 = configparser.ConfigParser()
		conf60568.add_section('section60568')
		conf60568.set('section60568', 'keyA-60568', 'a-Value')
		conf60568.set('section60568', 'keyB-60568', param)
		bar = conf60568.get('section60568', 'keyB-60568')

		try:
			doc = DefusedET.fromstring(bar)

			out = ''
			processing = [doc]
			while processing:
				e = processing.pop(0)
				if e.text:
					out += e.text
				processing[:0] = list(e)

			RESPONSE += (
				f'Your XML doc results are: <br>{escape_for_html(out)}'
			)
		except Exception as e:
			logger.error(f"XML parsing error: {type(e).__name__}")
			RESPONSE += (
				f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
			)

		return RESPONSE