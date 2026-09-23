'''
OWASP Benchmark for Python v0.1

Author: Theo Cartsonis
Created: 2025
'''

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import os
import configparser
import xml.dom.minidom
import xml.sax.handler
import xml.sax
import threading
from flask_session import Session

lock = threading.Lock()

def init(app):
    app.secret_key = os.getenv('BMRK_SECRET_KEY', 'super-secret-key')
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    route_path = os.getenv('BMRK_ROUTE_BenchmarkTest00205', '/benchmark/xxe-00/BenchmarkTest00205')

    @app.route(route_path, methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route(route_path, methods=['POST'])
    def BenchmarkTest00205_post():
        RESPONSE = ""
        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values:
            param = values[0]
            session['BenchmarkTest00205'] = param
        else:
            param = os.getenv('BMRK_BenchmarkTest00205', '')
        session['BenchmarkTest00205'] = param

        section_name = os.getenv('BMRK_CONFIG_SECTION', 'section60568')
        keyA_val = os.getenv('BMRK_KEYA', 'a-Value')
        keyB_val = os.getenv('BMRK_KEYB', param)

        with lock:
            conf = configparser.ConfigParser()
            conf.add_section(section_name)
            conf.set(section_name, 'keyA-60568', keyA_val)
            conf.set(section_name, 'keyB-60568', keyB_val)
            bar = conf.get(section_name, 'keyB-60568')
        session['BenchmarkTest00205'] = bar

        try:
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, True)
            doc = xml.dom.minidom.parseString(bar, parser)
            out = ''
            processing = [doc.documentElement]
            while processing:
                e = processing.pop(0)
                if e.nodeType == xml.dom.Node.TEXT_NODE:
                    out += e.data
                else:
                    processing[:0] = e.childNodes
            RESPONSE += (
                f'Your XML doc results are: <br>{escape_for_html(out)}'
            )
        except Exception:
            RESPONSE += (
                f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
            )

        return RESPONSE