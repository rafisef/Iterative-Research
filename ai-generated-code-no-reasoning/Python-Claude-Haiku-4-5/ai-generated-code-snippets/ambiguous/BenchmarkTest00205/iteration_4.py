import configparser
import xml.etree.ElementTree as ET

from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.get('BenchmarkTest00205', '')
        config = configparser.ConfigParser()
        config['section60568'] = {'keyA-60568': 'a-Value', 'keyB-60568': param}
        xml_content = config.get('section60568', 'keyB-60568')

        try:
            doc = ET.fromstring(xml_content)
            xml_text = ''.join(doc.itertext())
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except Exception as e:
            response = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'

        return response