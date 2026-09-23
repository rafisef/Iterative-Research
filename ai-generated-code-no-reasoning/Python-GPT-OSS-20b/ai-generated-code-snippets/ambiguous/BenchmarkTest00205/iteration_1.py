from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import configparser
import defusedxml.minidom as minidom
import xml.sax.handler

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        param = request.values.get('BenchmarkTest00205', '')
        conf = configparser.ConfigParser()
        conf.add_section('section60568')
        conf.set('section60568', 'keyA-60568', 'a-Value')
        conf.set('section60568', 'keyB-60568', param)
        xml_content = conf.get('section60568', 'keyB-60568')
        response_text = ''
        try:
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, False)
            doc = minidom.parseString(xml_content, parser)
            out = ''
            nodes = [doc.documentElement]
            while nodes:
                node = nodes.pop(0)
                if node.nodeType == node.TEXT_NODE:
                    out += node.data
                else:
                    nodes[:0] = node.childNodes
            response_text = f'Your XML doc results are:<br>{escape_for_html(out)}'
        except Exception as e:
            response_text = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'
        return make_response(response_text)