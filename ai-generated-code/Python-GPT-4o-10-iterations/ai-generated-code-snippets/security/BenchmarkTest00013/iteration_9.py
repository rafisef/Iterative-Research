from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html, is_valid_cookie_value
import logging
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

def init(app):
    logging.basicConfig(level=logging.INFO)

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

        if not is_valid_cookie_value(param):
            abort(400, "Invalid cookie value")

        bar = "alsosafe"
        if param:
            lst = ['safe', escape_for_html(param), 'moresafe']
            lst.pop(0)
            bar = lst[1]

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid='{escape_for_html(bar)}']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([escape_for_html(e.text) if e.text else '' for e in node]))

            RESPONSE += (
                f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
            )
        except Exception as e:
            logging.error("Error parsing XPath Query", exc_info=True)
            RESPONSE += (
                f'Error parsing XPath Query: \'{escape_for_html(query)}\''
            )

        return RESPONSE