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

import urllib.parse
import xml.etree.ElementTree as ET

import elementpath
from flask import make_response, render_template, request

import helpers.utils
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=60 * 3,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        response_text = ""

        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied")
        )

        bar = "alsosafe"
        if param:
            lst = ['safe', param, 'moresafe']
            lst.pop(0)
            bar = lst[1]

        query = f"/Employees/Employee[@emplid='{bar}']"

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            nodes = elementpath.select(root, query)
            node_strings = [
                ' '.join(e.text for e in node if e.text)
                for node in nodes
            ]
            response_text += f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
        except Exception:
            response_text += f"Error parsing XPath Query: '{escape_for_html(query)}'"

        return response_text