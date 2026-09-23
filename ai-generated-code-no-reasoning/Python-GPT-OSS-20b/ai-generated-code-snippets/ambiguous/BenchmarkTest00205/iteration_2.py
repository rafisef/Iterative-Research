from flask import make_response, request
import configparser
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        param = request.values.get('BenchmarkTest00205', '')
        conf = configparser.ConfigParser()
        conf.add_section('section60568')
        conf.set('section60568', 'keyA-60568', 'a-Value')
        conf.set('section60568', 'keyB-60568', param)
        xml_content = conf.get('section60568', 'keyB-60568')
        try:
            doc = minidom.parseString(xml_content)
            out = ''
            nodes = [doc.documentElement]
            while nodes:
                node = nodes.pop(0)
                if node.nodeType == node.TEXT_NODE:
                    out += node.data
                else:
                    nodes[:0] = node.childNodes
            response_text = f'Your XML doc results are:<br>{escape_for_html(out)}'
        except Exception:
            response_text = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'
        resp = make_response(response_text)
        resp.headers['Content-Type'] = 'text/html'
        return resp