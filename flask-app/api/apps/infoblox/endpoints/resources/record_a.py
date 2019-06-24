import logging
from flask import g, current_app, url_for
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response
from infoblox.Session import Session as infoblox_session
import infoblox.errors

class record_a(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type = str, required = True,
                help = 'No Hostname provided', location = 'json')
        self.reqparse.add_argument('view', type = str, required = True,
                help = 'No view provided', location = ['json', 'values'])
        self.reqparse.add_argument('addresses', type = str, required = True,
                help = 'No address provided', location = 'json')
        self.reqparse.add_argument('change_control', type = str, required = True,
                help = 'No change_control provided', location = 'json')
        self.reqparse.add_argument('domain', type = str, location = 'json')

        # Delete only really requires that we have change control
        self.delparse = reqparse.RequestParser()
        self.delparse.add_argument('change_control', type = str, required = True,
                help = 'No change_control provided', location = 'json')

        super(record_host, self).__init__()
        self.logger = logging.getLogger(__name__)

    # Create
    def post(self):
        args = self.reqparse.parse_args()
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = current_app.config.get('GRID_MASTER')
        domain      = current_app.config.get('DEFAULT_DOMAIN')

        self.logger.debug("method=post,user=%s,link=%s/%s/%s" % (
            user, args.get('view'), args.get('domain'), args.get('domain')
                ))

        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        if args.get('domain') != None:
            domain = args.get('domain')

        fqdn = ("%s.%s" % ( args.get('name'), domain)).lower()
        view = args.get('view')

        return rest_response_error(400, detail="TODO: Method not complete yet")

    # Retrieve
    def get(self, view=None, domain=None, name=None):
        user        = getattr(g, '_ibuser', None)
        auth_cookie = getattr(g, '_ibapauth', None)
        server      = current_app.config.get('GRID_MASTER')
        link        =  url_for('a_by_ref', view=view, domain=domain, name=name)

        self.logger.debug("method=get,user=%s,link=%s/%s/%s" % (
            user,view,domain,name
            ))
        if auth_cookie == None:
            self.logger.debug("No Auth cookie")
            # User wasn't authenicated or another error happened
            return rest_error_response(401)
        return rest_response_error(400, detail="TODO: Method not complete yet")

    # Update
    def put(self, view=None, domain=None, name=None):
        args = self.reqparse.parse_args()
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = current_app.config.get('GRID_MASTER')

        self.logger.debug("method=put,user=%s,link=%s/%s/%s" % (
            user, view, domain, name
                ))
        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        # Verify the view in the path and the view in the passed data
        #   match
        new_view = view
        if args.get('view') != view:
            self.logger.error("Views don't match: (%s / %s)" % ( view, args.get('view')))
            return rest_error_response(400, detail="Mismatching views")
        return rest_response_error(400, detail="TODO: Method not complete yet")

    # Delete
    def delete(self, view=None, domain=None, name=None):
        args = self.delparse.parse_args()
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = current_app.config.get('GRID_MASTER')

        self.logger.debug("method=delete,user=%s,link=%s/%s/%s" % (
            user, view, domain, name
        ))

        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        ib = infoblox_session(master=server, ibapauth=auth_cookie)

        return rest_response_error(400, detail="TODO: Method not complete yet")
