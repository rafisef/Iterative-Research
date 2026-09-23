from flask import Flask, request, Response
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

def register_routes(app: Flask) -> None:
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        xml_input = request.values.get('BenchmarkTest00205', '')
        try:
            doc = minidom.parseString(xml_input)
            nodes = [doc.documentElement]
            text_parts = []
            while nodes:
                node = nodes.pop(0)
                if node.nodeType == node.TEXT_NODE:
                    text_parts.append(node.data)
                else:
                    nodes[:0] = node.childNodes
            body = f'Your XML doc results are:<br>{escape_for_html("".join(text_parts))}'
        except Exception:
            body = f'There was an error reading your XML doc:<br>{escape_for_html(xml_input)}'
        return Response(body, mimetype='text/html')