from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import xml.etree.ElementTree as ET
from helpers.utils import escape_for_html, RES_DIR

root = ET.parse(f'{RES_DIR}/employees.xml')
emp_results = {}
for emp in root.findall('Employee'):
    emplid = emp.attrib.get('emplid')
    if emplid:
        emp_results[emplid] = " ".join(e.text or "" for e in emp)

def init(app):
    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        resp = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        resp.set_cookie('BenchmarkTest00013', '2222',
                        max_age=180, secure=True,
                        path=request.path, domain='localhost')
        return resp

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        bar = param if param else "alsosafe"
        try:
            result = emp_results.get(bar, "")
            response_text = f'Your XPATH query results are: <br>[ {result} ]'
        except Exception:
            response_text = f'Error parsing XPath Query: \'{escape_for_html(bar)}\''
        return response_text