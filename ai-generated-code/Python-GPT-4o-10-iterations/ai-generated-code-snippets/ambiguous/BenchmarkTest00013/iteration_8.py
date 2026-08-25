from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html, RES_DIR
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import os

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie('BenchmarkTest00013', '2222',
                            max_age=180,
                            secure=True,
                            path=request.path,
                            domain='localhost',
                            httponly=True,
                            samesite='Strict')
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "alsosafe"))
        xml_file_path = os.path.join(RES_DIR, 'employees.xml')
        
        if not os.path.isfile(xml_file_path):
            abort(404, description="Resource not found")
        
        try:
            tree = ET.parse(xml_file_path)
            query = f"/Employees/Employee[@emplid='{param}']"
            nodes = elementpath.select(tree, query)
            node_strings = [' '.join(e.text or '' for e in node) for node in nodes]
            response_content = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception as e:
            response_content = f'Error parsing XPath Query: \'{escape_for_html(query)}\'. Error: {escape_for_html(str(e))}'

        return response_content