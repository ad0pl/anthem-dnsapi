import os, sys
import logging
import re
import json
from logging.handlers import RotatingFileHandler

from flask import Flask, session, request, abort
from flask_restful import Api
import base64

sys.path.append(".")

from new_atm_dns_api_app.globals import GLOBALS
from new_atm_dns_api_app.infoblox.Session import Session as infoblox_session
from new_atm_dns_api_app.resources.record_host import record_host
from new_atm_dns_api_app.resources.views import InfobloxViews


def create_app(test_config=None):
  app = Flask(__name__, instance_relative_config=True)
  app.config.from_mapping(
          BUNDLE_ERRORS=True, 
          SECRET_KEY='dev'
  )

  if test_config is None:
      # load the instance config, if it exists, when not testing
      app.config.from_pyfile('config.py', silent=True)
  else:
      app.config.from_mapping(test_config)

  # ensure the instance folder exists
  try:
      os.makedirs(app.instance_path)
  except OSError:
      pass

  app.before_request(handle_session)
  app.after_request(disassocate_session)

  version = 0.1
  base_url = "/".join(["api", "v%s" % str(version)])
  api = Api(app)

  api.add_resource(InfobloxViews, "/%s/views" % base_url)
  # Host records
  api.add_resource(record_host, "/%s/record_host/<view>/<domain>/<name>" % base_url, endpoint="by_ref")
  api.add_resource(record_host, "/%s/record_host" % base_url)
  # Aliases records
  #api.add_resource(record_alias, "/%s/record_alias/<view>/<fqdn>" % base_url, endpoint="by_ref")
  #api.add_resource(record_alias, "/%s/record_alias" % base_url)
  # A records
  #api.add_resource(record_a, "/%s/record_a/<view>/<fqdn>" % base_url, endpoint="by_ref")
  #api.add_resource(record_a, "/%s/record_a" % base_url)

  return app, api

def handle_session():
    GLOBALS['ibapauth'] = request.cookies.get('ibapauth')
    auth_header = request.headers.get('Authorization')

    if GLOBALS['ibapauth'] == None and auth_header == None:
        # No infoblox token or auth header let them know we need somehting
        abort(401)
    elif GLOBALS['ibapauth'] != None:
        # Infoblox cookie was set, use that
        ib = infoblox_session (
                    master = GLOBALS['grid_master'],
                    ibapauth = GLOBALS['ibapauth']
        )
    elif auth_header != None:
        # They sent an Authorization header pass that on
        ib = infoblox_session (
                    master = GLOBALS['grid_master'],
                    auth_header = auth_header
            )
        try:
            ib.get("?_schema")
        except:
            abort(401)
        finally:
            if ib.session.cookies.get('ibapauth') != None:
              GLOBALS['ibapauth'] = ib.session.cookies.get('ibapauth').strip('"').rstrip('"')
            else:
              app.logger.error("No error but no cookie from Infoblox")
              abort(500)
    else:
        # We should never get here and something in the logic was wrong
        abort(503)
    GLOBALS['user']     = re.search(r'user=\w+', GLOBALS['ibapauth']).group(0).split("=")[1]
    logging.debug("User: %s" % GLOBALS['user'])
    pass

def disassocate_session(resp):
    if GLOBALS.get('ibapauth') != None:
      resp.set_cookie('ibapauth', GLOBALS['ibapauth'])
    GLOBALS['ibapauth'] = None
    GLOBALS['user']     = None
    return resp

(app, api) = create_app()

formatter=logging.Formatter(logging.BASIC_FORMAT)
handler = RotatingFileHandler('foo.log', maxBytes=10000, backupCount=1)
handler.setFormatter(formatter)

log = logging.getLogger('new_atm_dns_api_app')
log.setLevel(logging.DEBUG)
if not log.handlers:
  log.addHandler(handler)

@app.errorhandler(401)
def user_not_auth(error):
    ret_data = { 'status': "error", 'message': str(error) }
    return json.dumps(ret_data), 401

@app.errorhandler(403)
def user_bad_auth(error):
    ret = { 'status': "error", 'message': error }
    return json.dumps(ret), 403

@app.errorhandler(404)
def obj_not_found(error):
    ret = { 'status': "error", 'message': error }
    return json.dumps(ret), 404

if __name__ == '__main__':
    log.debug("Starting app")
    app.run(host="0.0.0.0", debug=True)

