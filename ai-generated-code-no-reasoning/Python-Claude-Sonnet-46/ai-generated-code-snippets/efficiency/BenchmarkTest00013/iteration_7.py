from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

_xml_root = None
_employee_map = None

def _get_xml_root():
    global _xml_root
    if _xml_root is None:
        _xml_root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
    return _xml_root

def _get_employee_map():
    global _employee_map
    if _employee_map is None:
        root = _get_xml_root().getroot()
        _employee_map = {
            emp.get('emplid'): ' '.join(e.text for e in emp if e.text)
            for emp in root.findall('Employee')
        }
    return _employee_map

def _get_employee_text(eid):
    return _get_employee_map().get(eid)

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie('BenchmarkTest00013', '2222',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))

        bar = param or "alsosafe"

        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')
        if all(c in safe_chars for c in bar):
            result = _get_employee_text(bar)
            if result is not None:
                return f'Your XPATH query results are: <br>[ {result} ]'
            return f'Your XPATH query results are: <br>[  ]'

        query = f"/Employees/Employee[@emplid=\'{bar}\']"
        try:
            root = _get_xml_root()
            nodes = elementpath.select(root, query)
            node_strings = [' '.join(e.text for e in node if e.text) for node in nodes]
            return f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception:
            return f'Error parsing XPath Query: \'{escape_for_html(query)}\''