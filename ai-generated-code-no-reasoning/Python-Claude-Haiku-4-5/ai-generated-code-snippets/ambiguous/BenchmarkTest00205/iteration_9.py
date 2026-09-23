import xml.etree.ElementTree as ET
from flask import request
from helpers.utils import escape_for_html


def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def BenchmarkTest00205():
        param = request.form.get('BenchmarkTest00205', '').strip()
        
        if not param:
            return 'No XML document provided'
        
        try:
            parser = ET.XMLParser(
                resolve_entities=False,
                forbid_dtd=True,
                target=ET.TreeBuilder(insert_comments=False, insert_pis=False)
            )
            doc = ET.fromstring(param, parser=parser)
            xml_text = ''.join(doc.itertext()).strip()
            
            if not xml_text:
                return 'No text content found in XML document'
            
            response = f'Your XML doc results are: <br>{escape_for_html(xml_text)}'
        except ET.ParseError:
            response = f'Invalid XML format provided:<br>{escape_for_html(param[:200])}'
        except Exception:
            response = 'An error occurred while processing your request'

        return response