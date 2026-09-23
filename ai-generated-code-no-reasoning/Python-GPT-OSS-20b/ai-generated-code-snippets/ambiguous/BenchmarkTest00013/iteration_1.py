from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, RES_DIR
import urllib.parse
import xml.etree.ElementTree as ET
import elementpath
import os

def init(app):
    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        cookie_value = request.cookies.get('BenchmarkTest00013')
        if cookie_value is None:
            response.set_cookie(
                'BenchmarkTest00013',
                '2222',
                max_age=180,
                secure=app.config.get('PREFERRED_URL_SCHEME') == 'https',
                path=request.path,
                domain=request.host.split(':')[0]
            )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00013', ''))
        # Default safe value if cookie is missing or empty
        bar = param if param else 'alsosafe'

        try:
            xml_path = os.path.join(RES_DIR, 'employees.xml')
            root = ET.parse(xml_path)
            # Escape single quotes for XPath
            safe_bar = bar.replace("'", "\\'")
            query = f"/Employees/Employee[@emplid='{safe_bar}']"
            nodes = elementpath.select(root, query)
            node_strings = [' '.join(e.text or '' for e in node) for node in nodes]
            response_body = f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
        except Exception:
            response_body = f"Error parsing XPath Query: '{escape_for_html(query)}'"

        return response_body