

import json

import flask
from flask import make_response
from youtube3.youtube import *

from apiclient import discovery
from oauth2client import client


app = flask.Flask(__name__)
import uuid

app.secret_key = str(uuid.uuid4())

YOUTUBE_READ_WRITE_SCOPE = "https://www.googleapis.com/auth/youtube"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"


def execute_command(http_auth ):
  youtube = Youtube(discovery.build(YOUTUBE_API_SERVICE_NAME , YOUTUBE_API_VERSION, http_auth))
  likedchannel = youtube.liked_channel()
  videos1 = youtube.videos_in_channels(likedchannel)
  videos2 = youtube.videos_in_channels(likedchannel, videos1['nextPageToken'] if 'nextPageToken' in videos1 else None )
  items = list(videos1.values()) + list(videos2.values())
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