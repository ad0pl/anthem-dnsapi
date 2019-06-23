import logging
from flask import g, current_app
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response

class record_host(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(record_host, self).__init__()
        self.logger = logging.getLogger(__name__)

    # Create
    def post(self):
        args = self.reqparse.parse_args()
        self.logger.debug("post")
        auth_cookie = getattr(g, '_ibapauth', None)
        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            ret = rest_error_response(401)
        else:
            ret = ({ }, 200)

        return ret

    # Retrieve
    def get(self, view=None, domain=None, name=None):
        self.logger.debug("get = %s/%s/%s" % (view,domain,name))
        auth_cookie = getattr(g, '_ibapauth', None)
        if auth_cookie == None:
            self.logger.debug("No Auth cookie")
            # User wasn't authenicated or another error happened
            return rest_error_response(401)
        else:
            self.logger.debug("Auth cookie Found")
        return { }, 200

    # Update
    def put(self, view=None, domain=None, name=None):
        self.logger.debug("put = %s/%s/%s" % (view,domain,name))
        auth_cookie = getattr(g, '_ibapauth', None)
        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            ret = rest_error_response(401)
        else:
            ret = ({ }, 200)
        return ret

    # Delete
    def delete(self, view=None, domain=None, name=None):
        self.logger.debug("delete = %s/%s/%s" % (view,domain,name))
        auth_cookie = getattr(g, '_ibapauth', None)
        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            ret = rest_error_response(401)
        else:
            ret = ({ }, 200)
        return ret
