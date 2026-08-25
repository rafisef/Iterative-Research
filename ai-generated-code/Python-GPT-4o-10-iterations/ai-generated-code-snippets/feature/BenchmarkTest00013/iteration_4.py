import os
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

class AuthProvider:
    def authenticate(self, request):
        raise NotImplementedError

class CookieAuthProvider(AuthProvider):
    def authenticate(self, request):
        return request.cookies.get(
            os.getenv("COOKIE_NAME", "BenchmarkTest00013"), 
            os.getenv("COOKIE_FALLBACK", "noCookieValueSupplied")
        )

class OAuthProvider(AuthProvider):
    def authenticate(self, request):
        return request.headers.get(
            os.getenv("AUTH_HEADER_NAME", "Authorization"), 
            os.getenv("TOKEN_FALLBACK", "noTokenSupplied")
        )

def init(app, auth_providers):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            os.getenv("COOKIE_NAME", "BenchmarkTest00013"), 
            os.getenv("COOKIE_VALUE", "2222"),
            max_age=int(os.getenv("COOKIE_MAX_AGE", 60*3)),
            secure=bool(int(os.getenv("COOKIE_SECURE", 1))),
            path=request.path,
            domain=os.getenv("COOKIE_DOMAIN", "localhost")
        )
        return response
        return BenchmarkTest00013_post()

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        RESPONSE = ""

        import urllib.parse

        param = "noAuthValueSupplied"
        for provider in auth_providers:
            param = provider.authenticate(request)
            if param != "noAuthValueSupplied":
                break

        param = urllib.parse.unquote_plus(param)

        bar = "alsosafe"
        if param:
            lst = []
            lst.append('safe')
            lst.append(param)
            lst.append('moresafe')
            lst.pop(0)
            bar = lst[1]

        import elementpath
        import xml.etree.ElementTree as ET
        import helpers.utils

        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([e.text for e in node]))

            RESPONSE += (
                f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
            )
        except:
            RESPONSE += (
                f'Error parsing XPath Query: \'{escape_for_html(query)}\''
            )

        return RESPONSE