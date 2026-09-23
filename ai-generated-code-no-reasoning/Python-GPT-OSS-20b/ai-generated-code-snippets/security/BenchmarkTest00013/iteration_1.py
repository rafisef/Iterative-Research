from flask import redirect, url_for, request, make_response, render_template
import re
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
from helpers.utils import escape_for_html, RES_DIR

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost',
            samesite='Strict'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        RESPONSE = ""
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", ""))
        if not re.match(r'^[a-zA-Z0-9]+$', param):
            param = ""
        bar = param if param else "alsosafe"

        try:
            root = ET.parse(f'{RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([escape_for_html(e.text or '') for e in node]))
            RESPONSE += f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception:
            RESPONSE += f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        return RESPONSE