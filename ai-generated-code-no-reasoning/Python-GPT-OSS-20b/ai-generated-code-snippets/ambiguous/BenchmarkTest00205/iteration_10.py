from flask import Flask, request, abort, Response
from defusedxml.minidom import parseString
from helpers.utils import escape_for_html

MAX_XML_SIZE = 1 << 20

def _extract_text(node):
    return node.textContent

def _get_xml_input():
    if request.method == 'POST':
        xml = request.get_data(as_text=True)
    else:
        xml = request.args.get('BenchmarkTest00205')
    if not xml:
        abort(400, description='Missing XML input')
    if request.content_length and request.content_length > MAX_XML_SIZE:
        abort(413, description='XML input exceeds maximum allowed size')
    if len(xml) > MAX_XML_SIZE:
        abort(413, description='XML input exceeds maximum allowed size')
    return xml

def _parse_xml(xml):
    doc = parseString(xml)
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