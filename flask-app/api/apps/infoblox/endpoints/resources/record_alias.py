import logging
from flask import g, current_app, url_for
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response
from infoblox.Session import Session as infoblox_session
import infoblox.errors

class record_alias(Resource):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type = str, required = True,
                help = 'No Hostname provided', location = 'json')
        self.reqparse.add_argument('view', type = str, required = True,
                help = 'No view provided', location = ['json', 'values'])
        self.reqparse.add_argument('canonical', type = str, required = True,
                help = 'No Canonical provided', location = 'json')
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

        payload = {
                'name': fqdn,
                'view': view,
                'comment': "host created by API",
                'canonical': args.get('canonical'),
                'extattrs': {
                    'Owner': { 'value': "DNSAPI" },
                    'change_number': { "value": args.get('change_control') },
                    }
                }
        ib = infoblox_session(master = server, ipauth=auth_cookie)
        # Check to make sure that the hostname isn't in use
        try:
            # We really need to check for ANY record types
            record_cname = ib.get("record:cname", {'name': fqdn, 'view': view})
        except infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials")
            return rest_error_response(401)
        except Exception as e:
            return rest_error_response(500, details="Something happened during checking existing: %s" % e.message )
        else:
            if len(record_cname) > 0:
                msg = "%s/%s - DNS Record in use" % (view,fqdn)
                self.logger.error(msg)
                return rest_error_response(400, detail="msg")
        # Everything looks okay, add it in
        record = None
        try:
            # The reference will have quotes around them
            _ref = ib.add("record:cname", payload).replace('"', '')
            ret = ib.get(_ref, {'_return_fields': "name,comment,canonical,disable,view,extattrs"})
        except infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials")
            return rest_error_response(403)
        except Exception as e:
            msg = "Unknown error: %s" % e.message
            self.logger.error("%s, payload=%s" % ( msg, str(payload) ))
            return rest_error_response(500, detail=msg)
        else:
            if isinstance(ret, list):
                if len(ret) > 0:
                    record = ret[0]
                else:
                    # No records were found
                    self.logger.error("%s/%s - Record created but not found" % (view,fqdn))
                    return rest_error_response(400, detail="Unknown error, record creation is undefined")
            elif isinstance(ret, dict) and ret.get('_ref') != None:
                record = ret
            else:
                self.logger.error("%s/%s - Invalid response from Infoblox: %s" % (view,fqdn,str(ret)))
                return rest_error_response(500)

        # We construct our successful response back to the client
        # Use the response back from infoblox but remove out the domain
        name = record.get('name').replace(".%s" % domain, "")
        response = {
                'name': name,
                'domain': domain,
                'comment': record.get('comment'),
                'canonical': record.get('canonical'),
                'view': record.get('view'),
                "link": url_for('by_ref', view=view, domain=domain, name=name)
                }
        
        log_msg = "|".join([
            view, domain, name,
            record.get('canonical')
            user,
            args.get('change_control')
            ])
        self.logger.info("NEWALIAS|%s" % log_msg)

        return response, 201

    # Retrieve
    def get(self, view=None, domain=None, name=None):
        user        = getattr(g, '_ibuser', None)
        auth_cookie = getattr(g, '_ibapauth', None)
        server      = current_app.config.get('GRID_MASTER')
        link        =  url_for('by_ref', view=view, domain=domain, name=name)

        self.logger.debug("method=get,user=%s,link=%s/%s/%s" % (
            user,view,domain,name
            ))
        if auth_cookie == None:
            self.logger.debug("No Auth cookie")
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        record_alias_query = {
                'name': "%s.%s" % (name,domain),
                'view': view,
                '_return_fields': "name,comment,view,canonical,extattrs"
        }
        ib = infoblox_session(master = server, ibapauth = auth_cookie)
        # TODO: At some point of time, this would be easier to do with
        #   field marshaling but haven't figured it out just yet
        host = { }
        try:
            ret = ib.get("record:cname", record_alias_query)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        else:
            if len(ret) == 0:
                return rest_error_response(404)
            elif len(ret) == 1:
                name = ret.get('name').replace(".%s" % domain, "")
                response = {
                        'name': name,
                        'domain': domain,
                        'comment': ret.get('comment'),
                        'view': ret.get('view'),
                        'canonical': ret.get('canonical')
                        'link': url_for('by_ref', view=view, domain=domain, name=name)
                        }
            else:
                self.logger.error("more than 1 record for %s" % link)
                return rest_error_response(400)

        return response, 200

    # Update
    def put(self, view=None, domain=None, name=None):
        pass

    # Delete
    def put(self, view=None, domain=None, name=None):
        pass
