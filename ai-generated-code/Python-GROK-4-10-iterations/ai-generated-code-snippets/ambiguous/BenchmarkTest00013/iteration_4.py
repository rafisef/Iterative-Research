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

import xml.etree.ElementTree as ET
from flask import redirect, url_for, request, make_response, render_template

import elementpath
import helpers.utils
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET', 'POST'])
    def BenchmarkTest00013():
        if request.method == 'GET':
            response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
            response.set_cookie('BenchmarkTest00013', '2222',
                max_age=60*3,
                secure=True,
                path=request.path,
                domain='localhost')
            return response

        param = request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied")
        bar = "alsosafe"
        if param:
            lst = ['safe', param, 'moresafe']
            lst.pop(0)
            bar = lst[0]

        query = None
        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(root, query)
            node_strings = [' '.join(e.text or '' for e in node) for node in nodes]
            return f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
        except Exception:
            safe_query = escape_for_html(query) if query else 'N/A'
            return f"Error parsing XPath Query: '{safe_query}'"