from flask import make_response, render_template, request, abort, current_app
import re
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
from helpers.utils import escape_for_html, RES_DIR

def init(app):
    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        host = request.host.split(':')[0]
        if host:
            domain = host
        else:
            domain = None
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=180,
            secure=current_app.config.get('SESSION_COOKIE_SECURE', True),
            httponly=True,
            path=request.path,
            domain=domain,
            samesite='Strict'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        raw = request.cookies.get('BenchmarkTest00013', '')
        param = urllib.parse.unquote_plus(raw)
        if not re.fullmatch(r'[A-Za-z0-9]+', param):
            abort(400)
        if len(param) > 50:
            abort(400)
        bar = param or 'alsosafe'
        try:
            parser = ET.XMLParser(resolve_entities=False)
            root = ET.parse(f'{RES_DIR}/employees.xml', parser=parser)
            query = f"/Employees/Employee[@emplid='{bar}']"
            nodes = elementpath.select(root, query)
            node_strings = [' '.join([escape_for_html(e.text or '') for e in node]) for node in nodes]
            response_text = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        except Exception:
            response_text = 'Error parsing XPath Query.'
        return response_text