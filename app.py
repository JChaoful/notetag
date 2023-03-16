import tempfile
import io
import logging

from flask import Flask, session, redirect, url_for, render_template, request, redirect, send_file, jsonify
from werkzeug.utils import secure_filename
import json
from authlib.integrations.flask_client import OAuth
from data.projectsecrets import secret_key
import sys

import google.oauth2.credentials
import googleapiclient.discovery

from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
from googleapiclient.errors import HttpError

app = Flask(__name__)

f = open('data/client_secret.json')
client_json = json.load(f)
app.secret_key = secret_key

CLIENT_ID = client_json['web']['client_id']
CLIENT_SECRET = client_json['web']['client_secret']
AUTH_URI = client_json['web']['auth_uri']
TOKEN_URI = client_json['web']['token_uri']

f.close()


oauth = OAuth(app)

# code to acquire refresh token
# https://stackoverflow.com/questions/62293888/obtaining-and-storing-refresh-token-using-authlib-with-flask
oauth.register (
    name='google',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url=AUTH_URI,
    access_token_url=TOKEN_URI,
    api_base_url='http://127.0.0.1:5000',
    client_kwargs={
        'scope': 'openid email profile https://www.googleapis.com/auth/drive.file'
    },
    authorize_params={'access_type': 'offline'},
    server_metadata_url= 'https://accounts.google.com/.well-known/openid-configuration'
)



# Google Drive API code based on:
# Documentation: https://developers.google.com/resources/api-libraries/documentation/drive/v3/python/latest/
# https://github.com/googleworkspace/gsuite-apis-intro
# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
def build_credentials():
    token = session['google-token']
    
    return google.oauth2.credentials.Credentials(
                token['access_token'],
                refresh_token=token['refresh_token'],
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                token_uri=TOKEN_URI)

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
def build_drive_api_v3():
    credentials = build_credentials()
    return googleapiclient.discovery.build('drive', 'v3', credentials=credentials).files()

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
def get_user_info():
    credentials = build_credentials()

    oauth2_client = googleapiclient.discovery.build(
                        'oauth2', 'v2',
                        credentials=credentials)

    return oauth2_client.userinfo().get().execute()

# Lists user's files to be displayed. Files should be in a user-specific notetag folder, that will be
# generated if it did not exist
def get_items():
    try:
        drive_api = build_drive_api_v3()
        user_id =  get_user_info()['id']
        root_fields = 'files(id,mimeType,appProperties)'
        # query help: https://stackoverflow.com/questions/48555368/how-can-i-search-custom-file-properties-using-the-google-drive-api
        root_query = 'mimeType="application/vnd.google-apps.folder" and appProperties has { key="rootID" and value="'+ user_id +'" }'

        root_results = drive_api.list(fields=root_fields, q=root_query).execute()

        if len(root_results['files']) > 0:
            file_fields = 'files(id,name,mimeType,createdTime,modifiedTime,shared,webContentLink, parents)'
            session['root_id'] = root_results['files'][0]['id']
            # should not display root folder
            file_query = '"' + session['root_id'] + '" in parents'
            return drive_api.list(fields=file_fields, q=file_query).execute()
        else: 
            # If there is no notetag folder, must either be user's first time or they deleted the folder in their drive
            # Either way, there should be no content
            # create notetag root folder
            generate_ids_result = drive_api.generateIds(count=1).execute()
            file_id = generate_ids_result['ids'][0]

            body = {
                'id': file_id,
                'name': 'notetag',
                'mimeType': 'application/vnd.google-apps.folder',
                'appProperties': {
                    'rootID': user_id,
                }
            }

            drive_api.create(body=body,
                            fields='id,name,mimeType,createdTime,modifiedTime,appProperties').execute()
            return {'files': []}
    except HttpError as error:
        print('An error occurred: %s' % error)   

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
def save_file(file_name, mime_type, file_data):
    try:
        drive_api = build_drive_api_v3()

        generate_ids_result = drive_api.generateIds(count=1).execute()
        file_id = generate_ids_result['ids'][0]

        body = {
            'id': file_id,
            'name': file_name,
            'mimeType': mime_type,
            'parents': [session['root_id']]
        }

        media_body = MediaIoBaseUpload(file_data,
                                    mimetype=mime_type,
                                    resumable=True)

        file = drive_api.create(body=body,
                        media_body=media_body,
                        fields='id,name,mimeType,createdTime,modifiedTime, parents').execute()

        return file_id
    except (HttpError, KeyError) as error:
        print('An error occurred: %s' % error)

# https://developers.google.com/drive/api/v2/reference/files/delete
def delete_file(file_id):
    try:
        drive_api = build_drive_api_v3()
        drive_api.delete(fileId=file_id).execute()
    except HttpError as error:
        print('An error occurred: %s' % error)

@app.route("/")
def index():
    try:
        # drive_api = build_drive_api_v3()
        # file_fields = 'files(id,name,mimeType,createdTime,modifiedTime,shared,webContentLink, parents)'
        # items2 = drive_api.list(fields=file_fields).execute()
        items = get_items()
        return render_template('list.html', files=items['files'], user_info=get_user_info())
    # If missing important session keys (authentication, root folder tracking), make user reauthenticate
    except KeyError:
        return redirect(url_for("login"))

@app.route("/login")
def login():
    redirect_uri = url_for('authorize', _external=True)
    print(redirect_uri, file=sys.stderr)
    return oauth.google.authorize_redirect(redirect_uri)
@app.route("/google-authorize")
def authorize():
    token = oauth.google.authorize_access_token()
    session['google-token'] = token
    return redirect('/')

@app.route('/logout')
def logout():
    session.pop('google-token', None)
    return redirect('/')

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
@app.route('/gdrive/upload', methods=['GET', 'POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect('/')

    file = request.files['file']
    if (not file):
        return redirect('/')
        
    filename = secure_filename(file.filename)

    fp = tempfile.TemporaryFile()
    ch = file.read()
    fp.write(ch)
    fp.seek(0)

    mime_type = request.headers['Content-Type']
    save_file(filename, mime_type, fp)

    return redirect('/')

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
@app.route('/gdrive/file/<file_id>', methods=['GET', 'DELETE'])
def process_file_request(file_id):
    if request.method == 'GET':
        drive_api = build_drive_api_v3()

        metadata = drive_api.get(fields="name,mimeType", fileId=file_id).execute()

        media_request = drive_api.get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, media_request)

        done = False
        while done is False:
            status, done = downloader.next_chunk()

        fh.seek(0)

        return send_file(
                        fh,
                        download_name=metadata['name'],
                        mimetype=metadata['mimeType']
                )
    # https://developers.google.com/drive/api/v2/reference/files/delete
    # https://stackoverflow.com/questions/61506681/python-flask-delete-request
    # https://stackoverflow.com/questions/48595068/process-ajax-request-in-flask
    # https://stackoverflow.com/questions/60582761/flask-return-redirect-not-working-after-delete
    # https://stackoverflow.com/questions/21756777/jquery-find-element-by-data-attribute-value
    elif request.method == 'DELETE':
        delete_file(file_id)
        return jsonify({ 'success': True })

    