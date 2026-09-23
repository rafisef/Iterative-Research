from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite
import logging

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		response.set_cookie('BenchmarkTest00011', 'bar',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
		
		if not isinstance(param, str) or len(param) > 1000:
			logger.warning("Invalid parameter received")
			return make_response("Invalid input", 400)

		bar = "This should never happen"
		if 'should' in bar:
			bar = param

		sql = 'SELECT username from USERS where password = ?'
		try:
			con = helpers.db_sqlite.get_connection()
			cur = con.cursor()
			cur.execute(sql, (bar,))
			RESPONSE += escape_for_html(helpers.db_sqlite.results(cur, sql))
			cur.close()
			con.close()
		except Exception as e:
			logger.error("Database error occurred")
			return make_response("An error occurred", 500)

		return RESPONSE