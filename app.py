from flask import Flask, redirect, url_for, session, request, render_template
from authlib.integrations.flask_client import OAuth
import requests
from dotenv import load_dotenv
import os
from functools import wraps
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key
app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET')
print(os.getenv('GITHUB_CLIENT_ID'))

oauth = OAuth(app)

#  register on the github developer platform to get the client key and secret key

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
# decorator is used to make the access of the different routes after the user session of the exits otherwise return back to the login page 

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

'''' sample  page routes '''
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login')
def login():
    redirect_uri = url_for('auth', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    token = github.authorize_access_token()
    ''' token verification is done with respect to the user'''
    resp = requests.get('https://api.github.com/user', headers={'Authorization': f'token {token["access_token"]}'})
    user_info = resp.json()
    '''user info and user info from are being verified '''
    session['user'] = user_info
    return redirect('/')

@app.route('/logout')
#  logout page route 
def logout():
    session.pop('user', None)
    return render_template('logout.html')

@app.route('/page1')
@login_required
def page1():
    return render_template('page1.html')

@app.route('/page2')
@login_required
def page2():
    return render_template('page2.html')

@app.route('/page3')
@login_required
def page3():
    return render_template('page3.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
