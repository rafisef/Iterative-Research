from flask import request
from helpers.utils import escape_for_html
import xml.sax

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        param = request.form.get('BenchmarkTest00205', '')
        if not param:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        class TextHandler(xml.sax.ContentHandler):
            def __init__(self):
                self.parts = []
            def characters(self, content):
                self.parts.append(content)
            def get_text(self):
                return ''.join(self.parts)
        handler = TextHandler()
        try:
            xml.sax.parseString(param, handler)
            out = handler.get_text()
        except xml.sax.SAXParseException:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        return f'Your XML doc results are: <br>{escape_for_html(out)}'