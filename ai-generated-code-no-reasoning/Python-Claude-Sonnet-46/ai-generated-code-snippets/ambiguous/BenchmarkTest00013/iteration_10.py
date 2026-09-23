import urllib.parse
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path
from typing import Optional

import elementpath
from flask import make_response, render_template, request, Response

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00013'
COOKIE_VALUE = '2222'
COOKIE_MAX_AGE = 180
ROUTE = '/benchmark/xpathi-00/BenchmarkTest00013'
SAFE_FALLBACK = "alsosafe"

_XPATH_REPLACEMENTS = str.maketrans({
    "'": "&apos;",
    '"': "&quot;",
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
})

_COOKIE_DEFAULTS = dict(
    max_age=COOKIE_MAX_AGE,
    secure=True,
    httponly=True,
    samesite='Strict',
    domain='localhost',
)


def init(app) -> None:

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00013_get() -> Response:
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(COOKIE_NAME, COOKIE_VALUE, path=request.path, **_COOKIE_DEFAULTS)
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00013_post() -> str:
        raw = request.cookies.get(COOKIE_NAME) or SAFE_FALLBACK
        param = urllib.parse.unquote_plus(raw)
        sanitized = _sanitize_xpath_param(param or SAFE_FALLBACK)
        return _execute_xpath_query(_build_query(sanitized))


def _sanitize_xpath_param(value: str) -> str:
    return value.translate(_XPATH_REPLACEMENTS)


def _build_query(bar: str) -> str:
    return f"/Employees/Employee[@emplid='{bar}']"


@lru_cache(maxsize=1)
def _load_xml_tree() -> ET.ElementTree:
    xml_path = Path(helpers.utils.RES_DIR) / 'employees.xml'
    if not xml_path.is_file():
        raise FileNotFoundError(f"XML resource not found: {xml_path}")
    return ET.parse(xml_path)


def _format_node(node: ET.Element) -> str:
    return ' '.join(e.text.strip() for e in node if e.text and e.text.strip())


def _get_node_text(node: object) -> Optional[str]:
    if not isinstance(node, ET.Element):
        return None
    text = _format_node(node)
    return text or None


def _execute_xpath_query(query: str) -> str:
    try:
        tree = _load_xml_tree()
        nodes = elementpath.select(tree, query)
        texts = [t for t in map(_get_node_text, nodes) if t]
        if not texts:
            return "Your XPATH query results are: <br>[ No results found. ]"
        escaped = escape_for_html(', '.join(texts))
        return f"Your XPATH query results are: <br>[ {escaped} ]"
    except FileNotFoundError as e:
        return f"Resource error: {escape_for_html(str(e))}"
    except elementpath.exceptions.ElementPathError:
        return f"Error parsing XPath Query: '{escape_for_html(query)}'"
    except ET.ParseError:
        return "Error parsing XML document."
    except Exception:
        return "An unexpected error occurred."