from flask import Flask, session, redirect, url_for
import json
from authlib.integrations.flask_client import OAuth
from data.projectsecrets import secret_key
import sys


app = Flask(__name__)

f = open('data/client_secret.json')
client_json = json.load(f)
app.secret_key = secret_key

client_id = client_json['web']['client_id']
client_secret = client_json['web']['client_secret']
auth_uri = client_json['web']['auth_uri']
token_uri = client_json['web']['token_uri']

f.close()


oauth = OAuth(app)

# code to acquire refresh token
# https://stackoverflow.com/questions/62293888/obtaining-and-storing-refresh-token-using-authlib-with-flask
oauth.register (
    name='google',
    client_id=client_id,
    client_secret=client_secret,
    authorize_url=auth_uri,
    access_token_url=token_uri,
    api_base_url='http://127.0.0.1:5000',
    client_kwargs={
        'scope': 'openid email profile https://www.googleapis.com/auth/drive.readonly.metadata'
    },
    authorize_params={'access_type': 'offline'},
    server_metadata_url= 'https://accounts.google.com/.well-known/openid-configuration'
)

@app.route("/")
def index():
    try:
        token = session['google-token']
    except KeyError:
        return redirect(url_for("login"))
    # print(dir(oauth.google), file=sys.stderr)
    # data = oauth.google.get('files', [])
    # for f in data:
    #     print(f['name'], f['mimeType'])
    return '<p>'+str(oauth.google.get('token', token=token)) + '</p>'
@app.route("/login")
def login():
    redirect_uri = url_for('authorize', _external=True)
    print(redirect_uri, file=sys.stderr)
    return oauth.google.authorize_redirect(redirect_uri)
@app.route("/google-authorize")
def authorize():
    token = oauth.google.authorize_access_token()
    session['google-token'] = token
    # print(token, file=sys.stderr)
    # print(token.get('refresh_token'), file=sys.stderr)
    # resp = oauth.google.get('account/verify_credentials.json')
    # resp.raise_for_status()
    # profile = resp.json()
    # print(oauth.google, file=sys.stderr)
    
    return token

@app.route('/logout')
def logout():
    session.pop('google-token', None)
    return redirect('/')
