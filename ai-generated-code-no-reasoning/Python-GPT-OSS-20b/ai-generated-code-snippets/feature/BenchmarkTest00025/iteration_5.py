import os
from flask import redirect, url_for, request, make_response, render_template, session

def init(app, config=None):
    env = {
        'BENCHMARK_COOKIE_DOMAIN': os.getenv('BENCHMARK_COOKIE_DOMAIN'),
        'BENCHMARK_COOKIE_MAX_AGE': os.getenv('BENCHMARK_COOKIE_MAX_AGE'),
        'BENCHMARK_COOKIE_SECURE': os.getenv('BENCHMARK_COOKIE_SECURE'),
        'AUTH_PROVIDERS': os.getenv('AUTH_PROVIDERS')
    }
    if config:
        env.update({f'BENCHMARK_{k.upper()}': v for k, v in config.items()})
    cookie_domain = env.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
    cookie_max_age = int(env.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
    secure_flag = str(env.get('BENCHMARK_COOKIE_SECURE', 'True')).lower() in ('true', '1', 'yes')
    providers = [p.strip() for p in env.get('AUTH_PROVIDERS', 'google,github').split(',')]

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025',
            'whatever',
            max_age=cookie_max_age,
            secure=secure_flag,
            path=request.path,
            domain=cookie_domain
        )
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ''
        import urllib.parse
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
        )
        superstring = f'90583{param}abcd'
        bar = superstring[len('90583'):len(superstring)-5]
        import random
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]
        if session.get(cookie) == value:
            RESPONSE += f'Welcome back: {user}<br/>'
        else:
            session[cookie] = value
            RESPONSE += (
                f'{user} has been remembered with cookie: '
                f'{cookie} whose value is: {session[cookie]}<br/>'
            )
        return RESPONSE

    @app.route('/auth/<provider>', methods=['GET'])
    def auth_provider(provider):
        if provider not in providers:
            return redirect(url_for('BenchmarkTest00025_get'))
        session['auth_provider'] = provider
        response = make_response(redirect(url_for('BenchmarkTest00025_get')))
        response.set_cookie(
            f'auth_{provider}',
            'token',
            max_age=cookie_max_age,
            secure=secure_flag,
            domain=cookie_domain
        )
        return response

    @app.route('/logout', methods=['GET'])
    def logout():
        session.pop('auth_provider', None)
        response = make_response(redirect(url_for('BenchmarkTest00025_get')))
        for provider in providers:
            response.delete_cookie(f'auth_{provider}', domain=cookie_domain)
        return response