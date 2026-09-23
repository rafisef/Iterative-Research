import configparser
import xml.dom.minidom
import xml.dom.Node
import xml.sax
import xml.sax.handler
from typing import Optional

from flask import Flask, Response, request
from helpers.utils import escape_for_html

_SAX_FEATURES: tuple[str, ...] = (
    xml.sax.handler.feature_external_ges,
    xml.sax.handler.feature_external_pes,
    xml.sax.handler.feature_namespaces,
)

_TRAVERSABLE_NODES: frozenset[int] = frozenset({
    xml.dom.Node.ELEMENT_NODE,
    xml.dom.Node.DOCUMENT_NODE,
})

_SECTION = "section60568"
_KEY = "keyB-60568"
_PARAM = "BenchmarkTest00205"
_ROUTE = "/benchmark/xxe-00/BenchmarkTest00205"
_MAX_PAYLOAD_BYTES = 1_048_576


def _make_safe_parser() -> xml.sax.xmlreader.XMLReader:
    parser = xml.sax.make_parser()
    for feature in _SAX_FEATURES:
        parser.setFeature(feature, False)
    return parser


def _extract_text_nodes(element: Optional[xml.dom.minidom.Element]) -> str:
    if element is None:
        return ""
    parts: list[str] = []
    stack: list[xml.dom.minidom.Node] = [element]
    while stack:
        node = stack.pop()
        if node.nodeType == xml.dom.Node.TEXT_NODE:
            text = node.data.strip()
            if text:
                parts.append(text)
        elif node.nodeType in _TRAVERSABLE_NODES:
            stack.extend(reversed(node.childNodes))
    return "".join(parts)


def _parse_xml(data: bytes) -> str:
    if len(data) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"Payload exceeds maximum allowed size of {_MAX_PAYLOAD_BYTES} bytes")
    doc = xml.dom.minidom.parseString(data, _make_safe_parser())
    try:
        return _extract_text_nodes(doc.documentElement)
    finally:
        doc.unlink()


def _get_param() -> str:
    conf = configparser.ConfigParser()
    conf.add_section(_SECTION)
    raw = next(iter(request.form.getlist(_PARAM)), "")
    conf.set(_SECTION, _KEY, raw)
    return conf.get(_SECTION, _KEY)


def _handle_xxe() -> tuple[str, int] | str:
    bar = _get_param()
    escaped = escape_for_html(bar)
    try:
        text_content = _parse_xml(bar.encode())
        return f"Your XML doc results are: <br>{escape_for_html(text_content)}"
    except xml.sax.SAXParseException:
        return f"There was an error reading your XML doc:<br>{escaped}", 400
    except ValueError as exc:
        return f"There was an error reading your XML doc:<br>{escape_for_html(str(exc))}", 413
    except Exception:
        return f"There was an error reading your XML doc:<br>{escaped}", 500


def init(app: Flask) -> None:
    app.route(_ROUTE, methods=["GET", "POST"])(_handle_xxe)