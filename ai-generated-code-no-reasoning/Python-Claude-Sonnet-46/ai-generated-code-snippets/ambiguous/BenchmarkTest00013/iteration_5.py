import urllib.parse
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

import elementpath
from flask import make_response, render_template, request

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


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00013_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        param = urllib.parse.unquote_plus(raw_cookie)
        bar = _resolve_bar(param)
        sanitized = _sanitize_xpath_param(bar)
        query = _build_query(sanitized)
        return _execute_xpath_query(query)


def _resolve_bar(param: str) -> str:
    if not param:
        return SAFE_FALLBACK
    lst = ['safe', param, 'moresafe']
    return lst[2]


def _sanitize_xpath_param(value: str) -> str:
    return value.translate(_XPATH_REPLACEMENTS)


def _build_query(bar: str) -> str:
    return f"/Employees/Employee[@emplid='{bar}']"


@lru_cache(maxsize=1)
def _load_xml_tree() -> ET.ElementTree:
    xml_path = Path(helpers.utils.RES_DIR) / 'employees.xml'
    return ET.parse(xml_path)


def _format_node(node: ET.Element) -> str:
    return ' '.join(e.text for e in node if e.text)


def _execute_xpath_query(query: str) -> str:
    try:
        root = _load_xml_tree()
        nodes = elementpath.select(root, query)
        result = ', '.join(
            _format_node(node) for node in nodes if isinstance(node, ET.Element)
        )
        return f"Your XPATH query results are: <br>[ {result} ]"
    except elementpath.exceptions.ElementPathError:
        return f"Error parsing XPath Query: '{escape_for_html(query)}'"
    except ET.ParseError:
        return "Error parsing XML document."
    except Exception:
        return "An unexpected error occurred."