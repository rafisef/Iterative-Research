from pathlib import Path
from flask import Blueprint, request, make_response, render_template, current_app as app
from helpers.utils import escape_for_html, RES_DIR
from urllib.parse import unquote_plus
import xml.etree.ElementTree as ET
import elementpath
from functools import lru_cache
from typing import List
import re

COOKIE_NAME = "BenchmarkTest00013"
DEFAULT_COOKIE_VALUE = "2222"
COOKIE_MAX_AGE = 180
XPATH_TEMPLATE = "/Employees/Employee[@emplid='{value}']"
XML_FILE = Path(RES_DIR) / "employees.xml"
MAX_XPATH_LENGTH = 256
XPATH_PATTERN = re.compile(r"^[A-Za-z0-9@./\[\]'\-]+$")

@lru_cache(maxsize=None)
def _parse_xml() -> ET.Element:
    return ET.parse(XML_FILE).getroot()

@lru_cache(maxsize=1024)
def _execute_xpath(value: str) -> List[str]:
    root = _parse_xml()
    query = XPATH_TEMPLATE.format(value=value.replace("'", "\\'"))
    nodes = elementpath.select(root, query)
    return [" ".join(escape_for_html(e.text or "") for e in node) for node in nodes]

def _sanitize(value: str) -> str:
    return value if len(value) <= MAX_XPATH_LENGTH and XPATH_PATTERN.match(value) else "alsosafe"

bp = Blueprint("benchmark", __name__)

@bp.route("/benchmark/xpathi-00/BenchmarkTest00013", methods=("GET", "POST"))
def benchmark():
    if request.method == "GET":
        resp = make_response(render_template("web/xpathi-00/BenchmarkTest00013.html"))
        if not request.cookies.get(COOKIE_NAME):
            resp.set_cookie(
                COOKIE_NAME,
                DEFAULT_COOKIE_VALUE,
                max_age=COOKIE_MAX_AGE,
                secure=request.is_secure,
                path=request.path,
                domain=request.host.split(":")[0],
            )
        return resp
    cookie_value = request.cookies.get(COOKIE_NAME, "")
    param = unquote_plus(cookie_value)
    bar = _sanitize(param)
    try:
        node_strings = _execute_xpath(bar)
        body = f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
    except Exception:
        body = f"Error parsing XPath Query: '{escape_for_html(str(bar))}'"
    return make_response(body)