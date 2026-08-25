from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import asyncio
import uuid
import os

def init(app):
    app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key_here')

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        session_id = session.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            session['session_id'] = session_id
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=int(os.getenv('COOKIE_MAX_AGE', 60*3)),
            secure=os.getenv('COOKIE_SECURE', 'True').lower() in ['true', '1', 't'],
            path=request.path,
            domain=os.getenv('COOKIE_DOMAIN', 'localhost')
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        return asyncio.run(handle_post_request())

    async def handle_post_request():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))

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
            root = await asyncio.to_thread(ET.parse, os.getenv('XML_FILE_PATH', f'{helpers.utils.RES_DIR}/employees.xml'))
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