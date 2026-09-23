import configparser
import xml.dom.minidom
import xml.etree.ElementTree as ET

from flask import request
from helpers.utils import escape_for_html


def _extract_xml_text(element):
    return ''.join(element.itertext())


def _parse_xml_safely(xml_content):
    return ET.fromstring(xml_content)


def _get_config_value(param):
    config = configparser.ConfigParser()
    config['section60568'] = {'keyA-60568': 'a-Value', 'keyB-60568': param}
    return config.get('section60568', 'keyB-60568')


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.get('BenchmarkTest00205', '')

        try:
            xml_content = _get_config_value(param)
            doc = _parse_xml_safely(xml_content)
            xml_text = _extract_xml_text(doc)
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except Exception as e:
            xml_content = _get_config_value(param)
            response = f'There was an error reading your XML doc:<br>{escape_for_html(xml_content)}'

        return response