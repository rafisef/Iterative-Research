from flask import request
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET
import io

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        param = request.values.get('BenchmarkTest00205', '')
        if not param:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        try:
            text_parts = []
            for _, elem in ET.iterparse(io.StringIO(param)):
                if elem.text:
                    text_parts.append(elem.text)
                if elem.tail:
                    text_parts.append(elem.tail)
                elem.clear()
            out = ''.join(text_parts)
        except ET.ParseError:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        return f'Your XML doc results are: <br>{escape_for_html(out)}'