import configparser
import xml.etree.ElementTree as ET

from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.get('BenchmarkTest00205', '')
        
        try:
            parser = ET.XMLParser(resolve_entities=False)
            doc = ET.fromstring(param, parser=parser)
            xml_text = ''.join(doc.itertext())
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except Exception as e:
            response = f'There was an error reading your XML doc:<br>{escape_for_html(param)}'

        return response