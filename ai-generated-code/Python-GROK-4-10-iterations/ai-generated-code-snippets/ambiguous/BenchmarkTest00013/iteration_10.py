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

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import ElementTree

import elementpath
import xml.etree.ElementTree as ET
from flask import Flask, Response, make_response, render_template, request

import helpers.utils
from helpers.utils import escape_for_html

logger = logging.getLogger(__name__)
XML_PATH: Path = Path(helpers.utils.RES_DIR) / 'employees.xml'
_XML_ROOT: ElementTree = ET.parse(XML_PATH)


def init(app: Flask) -> None:

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET', 'POST'])
    def BenchmarkTest00013() -> Any:
        if request.method == 'GET':
            resp: Response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
            resp.set_cookie(
                'BenchmarkTest00013',
                '2222',
                max_age=180,
                secure=True,
                httponly=True,
                samesite='Strict',
                path=request.path,
            )
            return resp

        param: str = request.cookies.get('BenchmarkTest00013', 'noCookieValueSupplied')
        bar: str = 'alsosafe'
        if param:
            lst = ['safe', param, 'moresafe']
            lst.pop(0)
            bar = lst[0]

        query: str | None = None
        try:
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(_XML_ROOT, query)
            node_strings = [' '.join((e.text or '') for e in node) for node in nodes]
            return f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
        except Exception:
            logger.exception('XPath processing error')
            safe_query = escape_for_html(query) if query else 'N/A'
            return make_response(f"Error parsing XPath Query: '{safe_query}'", 500)