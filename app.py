

import json

import flask
import httplib2
from flask import make_response

from apiclient import discovery
from oauth2client import client


app = flask.Flask(__name__)
import uuid

app.secret_key = str(uuid.uuid4())

YOUTUBE_READ_WRITE_SCOPE = "https://www.googleapis.com/auth/youtube"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"


def execute_command(http_auth ):
  youtube = discovery.build(YOUTUBE_API_SERVICE_NAME , YOUTUBE_API_VERSION, http_auth)
  #files =   youtube.channels().list(
  #     part='contentDetails', mine="true"
  #).execute()
  channels = youtube.channels().list(
      part='contentDetails', mine="true"
  ).execute()
  liked = channels['items'][0]['contentDetails']['relatedPlaylists']['likes']
  playlistItems = youtube.playlistItems().list(
          part='snippet', playlistId=liked
  ).execute()

  playlistItems2 = youtube.playlistItems().list(
      part='snippet', playlistId=liked, pageToken=playlistItems['nextPageToken'] if 'nextPageToken' in  playlistItems else None
  ).execute()
  items1 = playlistItems['items']
  items2 = playlistItems2['items']
  items = items1 + items2

  return json.dumps(items )


@app.route('/')
def index():
  if 'credentials' not in flask.session:
    return flask.redirect(flask.url_for('oauth2callback'))
  credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
  if credentials.access_token_expired:
    return flask.redirect(flask.url_for('oauth2callback'))
  else:
    http_auth = credentials.authorize(httplib2.Http())
    jsonret = execute_command(http_auth)
    resp = make_response(jsonret )
    resp.headers['Content-Type'] = 'application/json'
    return resp


@app.route('/oauth2callback')
def oauth2callback():
  flow = client.flow_from_clientsecrets(
      'client_secrets.json',
      scope='https://www.googleapis.com/auth/youtube',
      redirect_uri=flask.url_for('oauth2callback', _external=True))
  if 'code' not in flask.request.args:
    auth_uri = flow.step1_get_authorize_url()
    return flask.redirect(auth_uri)
  else:
    auth_code = flask.request.args.get('code')
    credentials = flow.step2_exchange(auth_code)
    flask.session['credentials'] = credentials.to_json()
    return flask.redirect(flask.url_for('index'))


if __name__ == '__main__':
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = False
  app.run()