import configparser
import xml.dom.minidom
import xml.dom.Node
import xml.sax
import xml.sax.handler

from flask import request
from helpers.utils import escape_for_html

_SAX_FEATURES = (
    xml.sax.handler.feature_external_ges,
    xml.sax.handler.feature_external_pes,
    xml.sax.handler.feature_namespaces,
)

_TRAVERSABLE_NODES = (xml.dom.Node.ELEMENT_NODE, xml.dom.Node.DOCUMENT_NODE)


def _make_safe_parser():
    parser = xml.sax.make_parser()
    for feature in _SAX_FEATURES:
        parser.setFeature(feature, False)
    return parser


def _extract_text_nodes(element):
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
        elif node.nodeType in _TRAVERSABLE_NODES:
            stack.extend(reversed(node.childNodes))
    return "".join(out)


def _parse_xml(data):
    parser = _make_safe_parser()
    doc = xml.dom.minidom.parseString(data, parser)
    try:
        return _extract_text_nodes(doc.documentElement)
    finally:
        doc.unlink()


def _get_param():
    conf = configparser.ConfigParser()
    conf.add_section("section60568")
    raw = next(iter(request.form.getlist("BenchmarkTest00205")), "")
    conf.set("section60568", "keyB-60568", raw)
    return conf.get("section60568", "keyB-60568")


def _handle_xxe():
    bar = _get_param()
    try:
        text_content = _parse_xml(bar.encode("utf-8"))
        return f"Your XML doc results are: <br>{escape_for_html(text_content)}"
    except xml.sax.SAXParseException:
        return f"There was an error reading your XML doc:<br>{escape_for_html(bar)}", 400
    except Exception:
        return f"There was an error reading your XML doc:<br>{escape_for_html(bar)}", 500


def init(app):
    app.route("/benchmark/xxe-00/BenchmarkTest00205", methods=["GET", "POST"])(
        _handle_xxe
    )