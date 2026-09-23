from flask import request
from markupsafe import escape
from anthropic import Anthropic

client = Anthropic()

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def BenchmarkTest00096():
        param = escape(request.values.get("BenchmarkTest00096", ""))
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=100,
            messages=[{
                "role": "user",
                "content": f"Analyze this user input for security concerns: '{param}'. Is it safe?"
            }]
        )
        
        security_analysis = response.content[0].text
        
        return f"bar is '{param}' and otherarg is 'static text' (security check: {security_analysis[:50]}...)"