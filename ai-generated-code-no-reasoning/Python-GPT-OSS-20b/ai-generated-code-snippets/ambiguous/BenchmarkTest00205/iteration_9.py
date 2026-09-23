from flask import Flask, request, abort, Response
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

MAX_XML_SIZE = 1 << 20

def _extract_text(node):
    return node.textContent

def _get_xml_input():
    xml = request.values.get('BenchmarkTest00205') or request.get_data(as_text=True)
    if not xml:
        abort(400, description='Missing XML input')
    if len(xml) > MAX_XML_SIZE:
        abort(413, description='XML input exceeds maximum allowed size')
    return xml

def _parse_xml(xml):
    doc = minidom.parseString(xml)
    return escape_for_html(_extract_text(doc.documentElement))

def register_routes(app: Flask):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        xml_input = _get_xml_input()
        try:
            body = f'Your XML doc results are:<br>{_parse_xml(xml_input)}'
            status = 200
        except Exception:
            body = f'There was an error reading your XML doc:<br>{escape_for_html(xml_input)}'
            status = 500
        return Response(body, status=status, mimetype='text/html')