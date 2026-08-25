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
from pathlib import Path
from typing import List

import elementpath
from flask import redirect, url_for, request, make_response, render_template
from helpers import utils
from helpers.utils import escape_for_html


COOKIE_NAME = "BenchmarkTest00013"
ROUTE_PATH = "/benchmark/xpathi-00/BenchmarkTest00013"


def init(app):

    @app.route(ROUTE_PATH, methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(COOKIE_NAME, '2222',
                            max_age=180,
                            secure=True,
                            path=request.path,
                            domain='localhost',
                            httponly=True,
                            samesite='Strict')
        return response

    @app.route(ROUTE_PATH, methods=['POST'])
    def BenchmarkTest00013_post():
        param: str = urllib.parse.unquote_plus(
            request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        )

        bar: str = "alsosafe"
        if param:
            lst: List[str] = ['safe', param, 'moresafe']
            lst.pop(0)
            bar = lst[0]

        query: str = f"/Employees/Employee[@emplid='{bar}']"
        try:
            xml_path = Path(utils.RES_DIR) / 'employees.xml'
            tree = ET.parse(xml_path)
            root = tree.getroot()
            nodes = elementpath.select(root, query)
            node_strings: List[str] = [
                ' '.join((e.text or '') for e in node) for node in nodes
            ]
            response_body = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except (ET.ParseError, OSError):
            response_body = f'Error parsing XPath Query: \'{escape_for_html(query)}\''

        return response_body