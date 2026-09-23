import configparser
import xml.dom.minidom
import xml.dom.Node
import xml.sax
import xml.sax.handler

from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = next(iter(request.form.getlist("BenchmarkTest00205")), "")

        conf = configparser.ConfigParser()
        conf.add_section('section60568')
        conf.set('section60568', 'keyB-60568', param)
        bar = conf.get('section60568', 'keyB-60568')

        try:
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, False)
            parser.setFeature(xml.sax.handler.feature_external_pes, False)
            parser.setFeature(xml.sax.handler.feature_namespaces, False)
            doc = xml.dom.minidom.parseString(bar.encode('utf-8'), parser)
            text_content = extract_text_nodes(doc.documentElement)
            doc.unlink()
            return f'Your XML doc results are: <br>{escape_for_html(text_content)}'
        except xml.sax.SAXParseException:
            return f'There was an error reading your XML doc:<br>{escape_for_html(bar)}', 400
        except Exception:
            return f'There was an error reading your XML doc:<br>{escape_for_html(bar)}', 500


def extract_text_nodes(element):
    if element is None:
        return ""
    stack = [element]
    out = []
    while stack:
        node = stack.pop()
        if node.nodeType == xml.dom.Node.TEXT_NODE:
            text = node.data.strip()
            if text:
                out.append(text)
        elif node.nodeType in (xml.dom.Node.ELEMENT_NODE, xml.dom.Node.DOCUMENT_NODE):
            stack.extend(reversed(node.childNodes))
    return "".join(out)