from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import logging

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
	def BenchmarkTest00078_get():
		response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
		response.set_cookie('BenchmarkTest00078', '',
			max_age=0,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
	def BenchmarkTest00078_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00078", ""))

		if not param:
			logger.warning("Empty cookie value received")
			return escape_for_html("Invalid input")

		string9895 = 'help'
		string9895 += param
		string9895 += 'snapes on a plane'
		bar = string9895[4:-17]

		import base64
		import helpers.utils

		helpers.utils.sharedstr = "no pickles to be seen here"

		try:
			decoded = base64.urlsafe_b64decode(bar)
			if len(decoded) > 10000:
				logger.warning("Decoded payload exceeds size limit")
				return escape_for_html("Payload too large")
			
			import json
			unpickled = json.loads(decoded.decode('utf-8'))
		except (ValueError, TypeError, UnicodeDecodeError) as e:
			logger.error(f"Deserialization failed: {type(e).__name__}")
			return escape_for_html("Deserialization failed")
		except Exception as e:
			logger.error(f"Unexpected error: {type(e).__name__}")
			return escape_for_html("An error occurred")

		RESPONSE += escape_for_html(
			f'shared string is {helpers.utils.sharedstr}'
		)

		return RESPONSE