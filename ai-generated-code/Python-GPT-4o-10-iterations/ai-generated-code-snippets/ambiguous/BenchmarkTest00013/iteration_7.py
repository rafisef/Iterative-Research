from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

def init(app):
    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def benchmark_test_00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013', '2222', max_age=180, secure=True, path=request.path, domain='localhost'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def benchmark_test_00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        bar = param or "alsosafe"

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml').getroot()
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(root, query)
            node_strings = [' '.join(e.text for e in node if e.text) for node in nodes]
            response_text = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception as e:
            response_text = f'Error parsing XPath Query: \'{escape_for_html(query)}\'. Exception: {escape_for_html(str(e))}'

        return response_text