from flask import Flask, request, abort, Response
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

MAX_XML_SIZE = 1 << 20

def _extract_text(node):
    return node.textContent

def register_routes(app: Flask):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        xml_input = request.values.get('BenchmarkTest00205') or request.get_data(as_text=True)
        if not xml_input:
            abort(400, description='Missing XML input')
        if len(xml_input) > MAX_XML_SIZE:
            abort(413, description='XML input exceeds maximum allowed size')
        try:
            doc = minidom.parseString(xml_input)
            body = f'Your XML doc results are:<br>{escape_for_html(_extract_text(doc.documentElement))}'
            status = 200
        except Exception as exc:
            body = f'There was an error reading your XML doc:<br>{escape_for_html(xml_input)}'
            status = 500
        return Response(body, status=status, mimetype='text/html')