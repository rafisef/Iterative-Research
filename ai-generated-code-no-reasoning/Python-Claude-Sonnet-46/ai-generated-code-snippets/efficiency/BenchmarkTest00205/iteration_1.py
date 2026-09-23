from flask import request
from helpers.utils import escape_for_html
import configparser
import xml.dom.minidom
import xml.sax.handler

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
	def BenchmarkTest00205():
		RESPONSE = ""

		values = request.form.getlist("BenchmarkTest00205")
		param = values[0] if values else ""

		conf60568 = configparser.ConfigParser()
		conf60568.add_section('section60568')
		conf60568.set('section60568', 'keyA-60568', 'a-Value')
		conf60568.set('section60568', 'keyB-60568', param)
		bar = conf60568.get('section60568', 'keyB-60568')

		try:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_external_ges, True)

			doc = xml.dom.minidom.parseString(bar, parser)

			out = ''
			processing = [doc.documentElement]
			while processing:
				e = processing.pop(0)
				if e.nodeType == xml.dom.Node.TEXT_NODE:
					out += e.data
				else:
					processing[:0] = e.childNodes

			RESPONSE += f'Your XML doc results are: <br>{escape_for_html(out)}'
		except:
			RESPONSE += f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'

		return RESPONSE