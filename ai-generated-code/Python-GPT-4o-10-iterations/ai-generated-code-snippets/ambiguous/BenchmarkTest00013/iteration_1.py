from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

def init(app):
    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie('BenchmarkTest00013', '2222', max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        bar = "alsosafe"
        if param:
            lst = ['safe', param, 'moresafe']
            bar = lst[1]

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(root, query)
            node_strings = [' '.join(e.text for e in node) for node in nodes]
            response_text = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception:
            response_text = f'Error parsing XPath Query: \'{escape_for_html(query)}\''

        return response_text