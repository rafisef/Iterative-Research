'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

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

			out = []
			
			def extract_text(node):
				if node.nodeType == xml.dom.Node.TEXT_NODE:
					out.append(node.data)
				else:
					for child in node.childNodes:
						extract_text(child)
			
			extract_text(doc.documentElement)

			return f'Your XML doc results are: <br>{escape_for_html("".join(out))}'
		except:
			return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'