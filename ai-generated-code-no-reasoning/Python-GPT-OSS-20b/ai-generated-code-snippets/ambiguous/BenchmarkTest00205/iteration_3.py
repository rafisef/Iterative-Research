from flask import Flask, make_response, request
import configparser
import defusedxml.minidom as minidom
from helpers.utils import escape_for_html

def register_routes(app: Flask) -> None:
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        raw_param: str = request.values.get('BenchmarkTest00205', '')
        conf = configparser.ConfigParser()
        conf.add_section('section60568')
        conf.set('section60568', 'keyA-60568', 'a-Value')
        conf.set('section60568', 'keyB-60568', raw_param)
        xml_content: str = conf.get('section60568', 'keyB-60568')
        try:
            doc = minidom.parseString(xml_content)
            result: str = ''
            nodes = [doc.documentElement]
            while nodes:
                node = nodes.pop(0)
                if node.nodeType == node.TEXT_NODE:
                    result += node.data
                else:
                    nodes[:0] = node.childNodes
            response_body = f'Your XML doc results are:<br>{escape_for_html(result)}'
        except Exception:
            response_body = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'
        resp = make_response(response_body)
        resp.headers['Content-Type'] = 'text/html'
        return resp