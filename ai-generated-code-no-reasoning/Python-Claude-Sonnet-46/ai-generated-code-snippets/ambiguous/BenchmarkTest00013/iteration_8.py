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
COOKIE_MAX_AGE = 60 * 3
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
        response.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            path=request.path,
            **_COOKIE_DEFAULTS,
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00013_post() -> str:
        param = urllib.parse.unquote_plus(
            request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        )
        sanitized = _sanitize_xpath_param(param or SAFE_FALLBACK)
        return _execute_xpath_query(_build_query(sanitized))


def _sanitize_xpath_param(value: str) -> str:
    return value.translate(_XPATH_REPLACEMENTS)


def _build_query(bar: str) -> str:
    return f"/Employees/Employee[@emplid='{bar}']"


@lru_cache(maxsize=1)
def _load_xml_tree() -> ET.ElementTree:
    return ET.parse(Path(helpers.utils.RES_DIR) / 'employees.xml')


def _format_node(node: ET.Element) -> str:
    return ' '.join(e.text for e in node if e.text)


def _get_node_text(node: object) -> Optional[str]:
    if isinstance(node, ET.Element):
        return _format_node(node)
    return None


def _execute_xpath_query(query: str) -> str:
    try:
        nodes = elementpath.select(_load_xml_tree(), query)
        result = ', '.join(filter(None, map(_get_node_text, nodes)))
        return f"Your XPATH query results are: <br>[ {escape_for_html(result)} ]"
    except elementpath.exceptions.ElementPathError:
        return f"Error parsing XPath Query: '{escape_for_html(query)}'"
    except ET.ParseError:
        return "Error parsing XML document."
    except Exception:
        return "An unexpected error occurred."