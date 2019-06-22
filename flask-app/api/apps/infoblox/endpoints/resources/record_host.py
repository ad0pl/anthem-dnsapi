import logging
from flask_restful import Resource, reqparse

class record_host(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        super(record_host, self).__init__()
        self.logger = logging.getLogger(__name__)

    # Create
    def post(self, view=None, domain=None, name=None):
        args = self.reqparse.parse_args()
        self.logger.debug("get = %s/%s/%s" % (view,domain,name))
        return { }, 404

    def post(self):
        args = self.reqparse.parse_args()
        self.logger.debug("post")
        return { }, 200

    # Retrieve
    def get(self, view=None, domain=None, name=None):
        self.logger.debug("get = %s/%s/%s" % (view,domain,name))
        return { }, 200

    # Update
    def put(self, view=None, domain=None, name=None):
        self.logger.debug("put = %s/%s/%s" % (view,domain,name))
        return { }, 200

    # Delete
    def delete(self, view=None, domain=None, name=None):
        self.logger.debug("delete = %s/%s/%s" % (view,domain,name))
        return { }, 200