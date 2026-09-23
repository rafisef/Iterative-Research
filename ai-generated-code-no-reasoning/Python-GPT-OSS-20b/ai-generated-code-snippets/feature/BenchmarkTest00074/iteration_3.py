import os
import sqlite3
import configparser
import urllib.parse
import asyncio
from flask import Flask, make_response, render_template, request, escape

def load_config(storage_type):
    config = {}
    if storage_type == 'file':
        conf_file = 'conf90091.ini'
        if os.path.exists(conf_file):
            conf = configparser.ConfigParser()
            conf.read(conf_file)
            if conf.has_section('section90091'):
                if conf.has_option('section90091', 'keyA-90091'):
                    config['keyA-90091'] = conf.get('section90091', 'keyA-90091')
                if conf.has_option('section90091', 'keyB-90091'):
                    config['keyB-90091'] = conf.get('section90091', 'keyB-90091')
    elif storage_type == 'db':
        db_file = 'conf90091.db'
        if os.path.exists(db_file):
            conn = sqlite3.connect(db_file)
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM config WHERE key IN ('keyA-90091','keyB-90091')")
            rows = cur.fetchall()
            for key, value in rows:
                config[key] = value
            conn.close()
    return config

async def load_config_async(storage_type):
    return await asyncio.to_thread(load_config, storage_type)

def init(app: Flask):
    storage_type = os.getenv('STORAGE_TYPE', 'env')

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    async def BenchmarkTest00074_post():
        RESPONSE = ""
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
        env_keyA = os.getenv('KEYA_90091', 'a-Value')
        env_keyB = os.getenv('KEYB_90091')
        use_keyB = env_keyB if env_keyB is not None else param
        conf_data = await load_config_async(storage_type)
        keyA = conf_data.get('keyA-90091', env_keyA)
        keyB = conf_data.get('keyB-90091', use_keyB)
        conf90091 = configparser.ConfigParser()
        conf90091.add_section('section90091')
        conf90091.set('section90091', 'keyA-90091', keyA)
        conf90091.set('section90091', 'keyB-90091', keyB)
        bar = conf90091.get('section90091', 'keyB-90091')
        try:
            exec(bar)
        except Exception as e:
            RESPONSE += f'Error executing statement \'{escape(bar)}\''
        return RESPONSE

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074-async', methods=['GET'])
    async def BenchmarkTest00074_get_async():
        response = make_response(await asyncio.to_thread(render_template, 'web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response