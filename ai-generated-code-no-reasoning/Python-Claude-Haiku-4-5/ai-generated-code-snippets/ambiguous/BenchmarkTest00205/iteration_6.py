import xml.etree.ElementTree as ET
from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.get('BenchmarkTest00205', '')
        
        if not param:
            return 'No XML document provided'
        
        try:
            parser = ET.XMLParser(resolve_entities=False, forbid_dtd=True)
            doc = ET.fromstring(param, parser=parser)
            xml_text = ''.join(doc.itertext())
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except ET.ParseError:
            response = f'Invalid XML format provided:<br>{escape_for_html(param[:200])}'
        except Exception as e:
            response = 'An error occurred while processing your request'

        return response