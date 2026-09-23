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

import asyncio
import uuid
import inspect
from threading import Lock
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html

def init(app):
	app.config['SECRET_KEY'] = str(uuid.uuid4())
	
	session_store = {}
	session_lock = Lock()

	def get_or_create_session():
		if 'session_id' not in session:
			session['session_id'] = str(uuid.uuid4())
		
		session_id = session['session_id']
		
		with session_lock:
			if session_id not in session_store:
				session_store[session_id] = {
					'data': {},
					'lock': Lock()
				}
		
		return session_id, session_store[session_id]

	def process_benchmark_test(param):
		RESPONSE = ""

		if not param:
			param = ""

		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = param
			case 'B':
				bar = 'bob'
			case 'C' | 'D':
				bar = param
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		RESPONSE += (
			f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
		)

		return RESPONSE

	async def process_benchmark_test_async(param):
		RESPONSE = ""

		if not param:
			param = ""

		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = param
			case 'B':
				bar = 'bob'
			case 'C' | 'D':
				bar = param
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		RESPONSE += (
			f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
		)

		await asyncio.sleep(0)
		return RESPONSE

	def execute_operation(operation_func, *args, **kwargs):
		if inspect.iscoroutinefunction(operation_func):
			return asyncio.run(operation_func(*args, **kwargs))
		else:
			return operation_func(*args, **kwargs)

	async def execute_operation_async(operation_func, *args, **kwargs):
		if inspect.iscoroutinefunction(operation_func):
			return await operation_func(*args, **kwargs)
		else:
			return operation_func(*args, **kwargs)

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
	def BenchmarkTest00096_get():
		return BenchmarkTest00096_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
	def BenchmarkTest00096_post():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			param = request.form.get("BenchmarkTest00096")
			result = execute_operation(process_benchmark_test, param)
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['GET'])
	async def BenchmarkTest00096_async_get():
		return await BenchmarkTest00096_async_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['POST'])
	async def BenchmarkTest00096_async_post():
		session_id, session_data = get_or_create_session()
		
		param = request.form.get("BenchmarkTest00096")
		result = await execute_operation_async(process_benchmark_test_async, param)
		
		with session_data['lock']:
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid', methods=['GET'])
	def BenchmarkTest00096_hybrid_get():
		return BenchmarkTest00096_hybrid_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid', methods=['POST'])
	def BenchmarkTest00096_hybrid_post():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			param = request.form.get("BenchmarkTest00096")
			result = execute_operation(process_benchmark_test_async, param)
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid-async', methods=['GET'])
	async def BenchmarkTest00096_hybrid_async_get():
		return await BenchmarkTest00096_hybrid_async_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid-async', methods=['POST'])
	async def BenchmarkTest00096_hybrid_async_post():
		session_id, session_data = get_or_create_session()
		
		param = request.form.get("BenchmarkTest00096")
		result = await execute_operation_async(process_benchmark_test, param)
		
		with session_data['lock']:
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/session/status', methods=['GET'])
	def get_session_status():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			return {
				'session_id': session_id,
				'data': session_data['data']
			}

	@app.route('/benchmark/session/status-async', methods=['GET'])
	async def get_session_status_async():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			await asyncio.sleep(0)
			return {
				'session_id': session_id,
				'data': session_data['data']
			}

	@app.route('/benchmark/session/clear', methods=['POST'])
	def clear_session():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			session_data['data'].clear()
		
		return {'status': 'cleared'}

	@app.route('/benchmark/session/clear-async', methods=['POST'])
	async def clear_session_async():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			session_data['data'].clear()
			await asyncio.sleep(0)
		
		return {'status': 'cleared'}