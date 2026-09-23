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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import re
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import secrets
import logging

logger = logging.getLogger(__name__)

SAFE_COOKIE_NAME = "BenchmarkTest00013"
ALLOWED_INPUT_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            SAFE_COOKIE_NAME,
            '2222',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get(SAFE_COOKIE_NAME, "noCookieValueSupplied")
        param = urllib.parse.unquote_plus(raw_cookie)

        bar = "alsosafe"
        if param:
            lst = []
            lst.append('safe')
            lst.append(param)
            lst.append('moresafe')
            lst.pop(0)
            bar = lst[1]

        if not ALLOWED_INPUT_PATTERN.match(bar):
            return escape_for_html(f'Invalid input: \'{bar}\''), 400

        try:
            xml_path = f'{helpers.utils.RES_DIR}/employees.xml'
            root = ET.parse(xml_path)

            nodes = elementpath.select(
                root,
                "/Employees/Employee[@emplid=$emplid]",
                variables={"emplid": bar}
            )

            node_strings = []
            for node in nodes:
                texts = [escape_for_html(e.text) for e in node if e.text is not None]
                node_strings.append(' '.join(texts))

            RESPONSE += (
                f'Your XPATH query results are: <br>[ {escape_for_html(", ".join(node_strings))} ]'
            )
        except ET.ParseError:
            logger.error("XML parse error in BenchmarkTest00013")
            RESPONSE += 'Error parsing XML resource.'
        except Exception:
            logger.error("Unexpected error in BenchmarkTest00013")
            RESPONSE += 'An unexpected error occurred.'

        return RESPONSE