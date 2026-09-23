from flask import Flask, request, Response, abort
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

MAX_XML_SIZE = 1 << 20  # 1 MB

def _extract_text(node):
    texts = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.nodeType == n.TEXT_NODE:
            texts.append(n.data)
        else:
            stack.extend(reversed(n.childNodes))
    return "".join(texts)

def register_routes(app: Flask) -> None:
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        xml_input = request.values.get('BenchmarkTest00205') or request.get_data(as_text=True)
        if not xml_input:
            abort(400)
        if request.content_length and request.content_length > MAX_XML_SIZE:
            abort(413)
        try:
            doc = minidom.parseString(xml_input)
            body = f'Your XML doc results are:<br>{escape_for_html(_extract_text(doc.documentElement))}'
        except Exception:
            body = f'There was an error reading your XML doc:<br>{escape_for_html(xml_input)}'
        return Response(body, mimetype='text/html')