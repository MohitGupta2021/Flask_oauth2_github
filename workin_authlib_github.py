''' Basic configuration to be work with OAuth github '''
from flask import Flask, redirect, url_for, session, request, render_template_string
from authlib.integrations.flask_client import OAuth
import requests
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key
app.config['GITHUB_CLIENT_ID'] = 'Ov23liLTiKBGHs9ezeHB'  # Replace with your GitHub client ID
app.config['GITHUB_CLIENT_SECRET'] = 'ae27b6419d2f68000e21a5c8e531ec31ae72ee06'  # Replace with your GitHub client secret


oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/auth',
    scope='user:email',
    client_kwargs={'scope': 'user:email'}
)

@app.route('/')
def home():
    if 'user' in session:
        return f'Logged in as {session["user"]["login"]}. <a href="/logout">Logout</a>'
    return 'You are not logged in. <a href="/login">Login with GitHub</a>'

@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    token = github.authorize_access_token()
    resp = requests.get('https://api.github.com/user', headers={'Authorization': f'token {token["access_token"]}'})
    user_info = resp.json()
    session['user'] = user_info
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
