import os
import configparser
import xml.dom.minidom
import xml.sax.handler
import xml.sax
from flask import Flask, redirect, url_for, request, make_response, render_template, session
from flask_session import Session
from helpers.utils import escape_for_html

def init(app: Flask):
    app.secret_key = os.getenv('BMRK_SECRET_KEY', 'super-secret-key')
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = os.getenv('BMRK_REDIS_URL', 'redis://localhost:6379')
    app.config['SESSION_FILE_DIR'] = os.getenv('BMRK_SESSION_DIR', './flask_session')
    Session(app)
    route_path = os.getenv('BMRK_ROUTE_BenchmarkTest00205', '/benchmark/xxe-00/BenchmarkTest00205')

    @app.route(route_path, methods=['GET'])
    def benchmark_test_00205_get():
        return benchmark_test_00205_post()

    @app.route(route_path, methods=['POST'])
    def benchmark_test_00205_post():
        response = ""
        values = request.form.getlist("BenchmarkTest00205")
        param = values[0] if values else os.getenv('BMRK_BenchmarkTest00205', '')
        session['BenchmarkTest00205'] = param

        section_name = os.getenv('BMRK_CONFIG_SECTION', 'section60568')
        key_a_val = os.getenv('BMRK_KEYA', 'a-Value')
        key_b_val = os.getenv('BMRK_KEYB', param)

        conf = configparser.ConfigParser()
        conf.add_section(section_name)
        conf.set(section_name, 'keyA-60568', key_a_val)
        conf.set(section_name, 'keyB-60568', key_b_val)
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
            response += f'Your XML doc results are: <br>{escape_for_html(out)}'
        except Exception:
            response += f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
        return response