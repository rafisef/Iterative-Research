import urllib.parse
import xml.etree.ElementTree as ET

import elementpath
from flask import make_response, render_template, request

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00013'
COOKIE_VALUE = '2222'
COOKIE_MAX_AGE = 60 * 3


def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            COOKIE_NAME,
            COOKIE_VALUE,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
        )

        bar = resolve_bar(param)
        query = build_query(bar)

        return execute_xpath_query(query)


def resolve_bar(param):
    if not param:
        return "alsosafe"
    lst = ['safe', param, 'moresafe']
    lst.pop(0)
    return lst[1]


def build_query(bar):
    return f"/Employees/Employee[@emplid='{bar}']"


def execute_xpath_query(query):
    try:
        root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
        nodes = elementpath.select(root, query)
        node_strings = [
            ' '.join(e.text for e in node if e.text)
            for node in nodes
        ]
        return f"Your XPATH query results are: <br>[ {', '.join(node_strings)} ]"
    except Exception:
        return f"Error parsing XPath Query: '{escape_for_html(query)}'"