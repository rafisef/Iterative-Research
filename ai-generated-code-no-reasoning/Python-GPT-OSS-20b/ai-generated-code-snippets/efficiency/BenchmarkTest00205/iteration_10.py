@app.route('/xml', methods=['POST'])
def parse_xml():
    param = request.values.get('BenchmarkTest00205', '')
    escaped_param = escape_for_html(param)
    if not param:
        return f'There was an error reading your XML doc:<br>{escaped_param}'
    try:
        root = ET.fromstring(param)
        parts = [f'{elem.text}<br>' for elem in root.iter('value') if elem.text]
        return ''.join(parts)
    except Exception:
        return f'There was an error reading your XML doc:<br>{escaped_param}'