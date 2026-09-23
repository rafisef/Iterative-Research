from flask import (
    redirect, url_for, request, make_response, render_template,
    current_app as app
)
from helpers.utils import escape_for_html, RES_DIR
import urllib.parse
import xml.etree.ElementTree as ET
import elementpath
import os

COOKIE_NAME = "BenchmarkTest00013"
DEFAULT_COOKIE_VALUE = "2222"
COOKIE_MAX_AGE = 180
XPATH_TEMPLATE = "/Employees/Employee[@emplid='{value}']"
XML_FILE = os.path.join(RES_DIR, "employees.xml")

def init(app):
    @app.route("/benchmark/xpathi-00/BenchmarkTest00013", methods=["GET"])
    def get_benchmark():
        resp = make_response(
            render_template("web/xpathi-00/BenchmarkTest00013.html")
        )
        if not request.cookies.get(COOKIE_NAME):
            resp.set_cookie(
                COOKIE_NAME,
                DEFAULT_COOKIE_VALUE,
                max_age=COOKIE_MAX_AGE,
                secure=app.config.get("PREFERRED_URL_SCHEME") == "https",
                path=request.path,
                domain=request.host.split(":")[0],
            )
        return resp

    @app.route("/benchmark/xpathi-00/BenchmarkTest00013", methods=["POST"])
    def post_benchmark():
        cookie_value = request.cookies.get(COOKIE_NAME, "")
        param = urllib.parse.unquote_plus(cookie_value)
        bar = param if param else "alsosafe"
        try:
            root = ET.parse(XML_FILE).getroot()
            query = XPATH_TEMPLATE.format(value=bar.replace("'", "\\'"))
            nodes = elementpath.select(root, query)
            node_strings = [
                " ".join(e.text or "" for e in node) for node in nodes
            ]
            body = f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
        except Exception:
            body = f"Error parsing XPath Query: '{escape_for_html(query)}'"
        return body