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
import xml.dom.Node
import xml.sax
import xml.sax.handler

from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.getlist("BenchmarkTest00205")
        param = param[0] if param else ""

        conf = configparser.ConfigParser()
        conf.add_section('section60568')
        conf.set('section60568', 'keyA-60568', 'a-Value')
        conf.set('section60568', 'keyB-60568', param)
        bar = conf.get('section60568', 'keyB-60568')

        try:
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, True)

            doc = xml.dom.minidom.parseString(bar, parser)

            out = []
            processing = [doc.documentElement]
            while processing:
                e = processing.pop(0)
                if e.nodeType == xml.dom.Node.TEXT_NODE:
                    out.append(e.data)
                else:
                    processing[:0] = list(e.childNodes)

            return f'Your XML doc results are: <br>{escape_for_html("".join(out))}'
        except Exception:
            return f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'