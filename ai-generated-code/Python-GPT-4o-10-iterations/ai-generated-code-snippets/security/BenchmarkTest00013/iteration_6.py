from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import re

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie('BenchmarkTest00013', '2222',
                            max_age=60*3,
                            secure=True,
                            httponly=True,
                            samesite='Strict',
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        RESPONSE = ""

        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))

        bar = "alsosafe"
        if param:
            if re.match(r'^[\w\d]+$', param):  # Ensure param is alphanumeric
                lst = ['safe', param, 'moresafe']
                bar = lst[1]
            else:
                abort(400)

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid=\'{escape_for_html(bar)}\']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([e.text for e in node if e.text is not None]))

            RESPONSE += (
                f'Your XPATH query results are: <br>[ {escape_for_html(", ".join(node_strings))} ]'
            )
        except Exception as e:
            RESPONSE += (
                f'Error parsing XPath Query'
            )
            abort(400)

        return RESPONSE