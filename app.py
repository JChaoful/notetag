import tempfile
import io
import logging
import pickle

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

# Lists user's files to be displayed initially (in the root notetag folder). Files should be in a user-specific notetag folder, 
# that will be generated if it did not exist
def get_items():
    # pickle to cache queries: https://stackoverflow.com/questions/19201290/how-to-save-a-dictionary-to-a-file
    results_location = 'data/results.pkl'

    # Check if files stored locally
    if 'results' not in session:
        drive_api = build_drive_api_v3()
        drive_fields = 'files(id,name,mimeType,shared,webContentLink, appProperties, parents, trashed)'
        drive_query = 'trashed = false'
        drive_results = drive_api.list(fields=drive_fields, q=drive_query).execute()
        
        with open(results_location, 'wb') as f:
            pickle.dump(drive_results, f)

        session['results'] = results_location

    with open(results_location, 'rb') as f:
        pickled_results = pickle.load(f)
    # Try to find the root folder, if any
    root_results = list(filter(lambda x: (x['mimeType']=='application/vnd.google-apps.folder' and ('appProperties' in x)
                                      and x['appProperties'].get('sourceID') == 'notetag'), pickled_results['files']))
    

    if len(root_results) > 0:
        # If user was inactive too long, and session variables were cleared, reset them
        if not 'root_id' in session or not 'directory' in session:
            root_id = root_results[0]['id']
            session['root_id'] = root_id
            # file_query = '"' + session['root_id'] + '" in parents'
            session['directory'] = {
                'parent': root_id,
                'current': root_id
            }
            # Find all directories directly under the root
            root_children = list(filter(lambda x: session['root_id'] in x['parents'], pickled_results['files']))
            return {'files': root_children}
        # Otherwise load all files in the currently viewed directory
        else:
            # file_query = '"' + session['directory']['current'] + '" in parents'
            current_children = list(filter(lambda x: session['directory']['current'] in x['parents'], pickled_results['files']))
            return {'files': current_children}
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
                'sourceID': 'notetag',
            }
        }

        output = drive_api.create(body=body,
                    fields='id,name,mimeType,appProperties').execute()
        
        session['root_id'] = file_id
        session['directory'] = {
            'parent': file_id,
            'current': file_id
        }

        return {'files': []} 

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
            'parents': [session['directory']['current']]
        }

        media_body = MediaIoBaseUpload(file_data,
                                    mimetype=mime_type,
                                    resumable=True)
        

        drive_api.create(body=body,
            media_body=media_body,
            fields='id,name,mimeType,shared,webContentLink, appProperties, parents').execute()
        # Check if database updated next render
        session.pop('results', None)
        return file_id
    except HttpError as error:
        # Operation failed, display error
        # Check if stored files match database
        session.pop('results', None)


def save_folder(file_name):
    try:
        drive_api = build_drive_api_v3()

        generate_ids_result = drive_api.generateIds(count=1).execute()
        file_id = generate_ids_result['ids'][0]

        body = {
            'id': file_id,
            'name': file_name,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [session['directory']['current']]
        }

        drive_api.create(body=body,
            fields='id,name,mimeType,createdTime,modifiedTime, parents').execute()

        # Check if database updated next render
        session.pop('results', None)
        return file_id
    except HttpError as error:
        # Operation failed, display error
        # Check if stored files match database
        session.pop('results', None)


# https://developers.google.com/drive/api/v2/reference/files/delete
def delete_file(file_id):
    try:
        drive_api = build_drive_api_v3()
        drive_api.delete(fileId=file_id).execute()
        # Check if database updated next render
        session.pop('results', None)
    except HttpError as error:
        # Operation failed, display error
        # Check if stored files match database
        session.pop('results', None)


@app.route("/")
def index():
    try:
        items = get_items()
        return render_template('list.html', files=items['files'], user_info=get_user_info(), root_id=session['root_id'],
                               parent_id=session['directory']['parent'])
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
    session.pop('root-id', None)
    session.pop('directory', None)
    session.pop('results', None)
    return redirect('/')

# https://www.mattbutton.com/2019/01/05/google-authentication-with-python-and-flask/
@app.route('/gdrive/upload', methods=['GET', 'POST'])
def upload_file():
    # Form as submitted from folder uploader
    if len(request.form) > 0:
        folder_name = secure_filename(request.form.getlist('folder-name')[0])
        # Ignore empty-named folder requests
        if folder_name == '':
            return redirect('/')
        
        save_folder(folder_name)

    # Form was submitted from file uploader
    else:
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

        metadata = drive_api.get(fields="name,mimeType,parents", fileId=file_id).execute()

        # if the requested file is a folder, update the current directory instead
        if metadata['mimeType'] =='application/vnd.google-apps.folder':
            # Cannot view files above the notetag directory, edge case
            if file_id == session['root_id']:
                session['directory'] = {
                    'parent': file_id,
                    'current': file_id
                }
            else:
                session['directory'] = {
                    'parent': metadata['parents'][0],
                    'current': file_id
                }
            # Ajax response code/response usage: https://stackoverflow.com/questions/36620864/passing-variables-from-flask-back-to-ajax
            files = get_items()['files']

            # rerender jinja loop with ajax https://stackoverflow.com/questions/40391566/render-jinja-after-jquery-ajax-request-to-flask
            return jsonify({
                'files': render_template('tablebody.html', files=files),
                'parent_id': session['directory']['parent'],
                'root_id': session['root_id']
                })

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

    