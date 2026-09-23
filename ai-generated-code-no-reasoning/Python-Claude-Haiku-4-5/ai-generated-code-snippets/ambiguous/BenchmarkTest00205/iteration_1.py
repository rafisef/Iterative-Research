'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

import configparser
import xml.dom.minidom
import xml.sax.handler

from flask import request
from helpers.utils import escape_for_html


def _extract_xml_text(doc):
    out = ''
    processing = [doc.documentElement]
    while processing:
        e = processing.pop(0)
        if e.nodeType == xml.dom.Node.TEXT_NODE:
            out += e.data
        else:
            processing[:0] = e.childNodes
    return out


def _parse_xml_with_xxe(xml_content):
    parser = xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_external_ges, True)
    return xml.dom.minidom.parseString(xml_content, parser)


def _get_config_value(param):
    config = configparser.ConfigParser()
    config.add_section('section60568')
    config.set('section60568', 'keyA-60568', 'a-Value')
    config.set('section60568', 'keyB-60568', param)
    return config.get('section60568', 'keyB-60568')


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        values = request.form.getlist("BenchmarkTest00205")
        param = values[0] if values else ""

        try:
            xml_content = _get_config_value(param)
            doc = _parse_xml_with_xxe(xml_content)
            xml_text = _extract_xml_text(doc)
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except Exception as e:
            xml_content = _get_config_value(param)
            response = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'

        return response