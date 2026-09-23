from flask import make_response, request, render_template
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from helpers.utils import RES_DIR

_EMP_DATA = {}
try:
    xml_path = Path(RES_DIR) / "employees.xml"
    root = ET.parse(xml_path).getroot()
    for elem in root.iter("Employee"):
        emplid = elem.attrib.get("emplid")
        if emplid:
            _EMP_DATA[emplid] = " ".join(e.text or "" for e in elem)
except Exception:
    _EMP_DATA = {}

def get_emp_result(emplid):
    return _EMP_DATA.get(emplid, "")

def init(app):
    @app.route("/benchmark/xpathi-00/BenchmarkTest00013", methods=["GET"])
    def BenchmarkTest00013_get():
        resp = make_response(render_template("web/xpathi-00/BenchmarkTest00013.html"))
        resp.set_cookie(
            "BenchmarkTest00013",
            "2222",
            max_age=180,
            secure=True,
            path=request.path,
            domain="localhost",
        )
        return resp

    @app.route("/benchmark/xpathi-00/BenchmarkTest00013", methods=["POST"])
    def BenchmarkTest00013_post():
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied")
        )
        bar = param or "alsosafe"
        result = get_emp_result(bar)
        return f"Your XPATH query results are: <br>[ {result} ]"