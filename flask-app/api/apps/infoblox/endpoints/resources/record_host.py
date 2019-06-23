import logging
from flask import g, current_app, url_for
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response

class record_host(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('name', type = str, required = True,
                help = 'No Hostname provided', location = 'json')
        self.reqparse.add_argument('view', type = str, required = True,
                help = 'No view provided', location = ['json', 'values'])
        self.reqparse.add_argument('address', type = str, required = True,
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
        self.logger.debug("post")
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = getattr(current_app.config, 'GRID_MASTER', None)
        domain      = getattr(current_app.config, 'DEFAULT_DOMAIN', None)


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
                'ipv4addrs': [ { 'ipv4addr': args.get('address') } ],
                'extattrs': {
                    'Owner': { 'value': "DNSAPI" },
                    'change_number': { "value": args.get('change_control') },
                    }
                }
        ib = infoblox_session(master = server, ipauth=auth_cookie)
        # Check to make sure that the hostname isn't in use
        #   Or that the address isn't in use
        try:
            record_host = ib.get("record:host", {'name': fqdn, 'view': view})
            record_addr = ib.get("record:host_ipv4addr", {'ipv4addr': args.get('address'), 'network_view': "default"})
        except infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials")
            return rest_error_response(401)
        except Exception as e:
            return rest_error_response(500, details="Something happened during checking existing: %s" % e.message )
        else:
            if len(record_host) > 0:
                msg = "%s/%s - DNS Record in use" % (view,fqdn)
                self.logger.error(msg)
                return rest_error_response(400, detail="msg")
            if len(record_addr) > 0:
                msg = "%s - Address in use" % (args.get('address'))
                self.logger.error(msg)
                return rest_error_response(400, detail="msg")

        # Everything looks okay, add it in
        record = None
        try:
            # The reference will have quotes around them
            _ref = ib.addr("record:host", payload).replace('"', '')
            ret = ib.get(_ref, {'_return_fields': "name,comment,ipv4addrs,disable,view,extattrs"})
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
        host = {
                'name': name,
                'domain': domain,
                'comment': record.get('comment'),
                'address': record.get('ipv4addrs')[0].get('ipv4addr'),
                'view': record.get('view'),
                "link": url_for('by_ref', view=view, domain=domain, name=name)
                }

        log_msg = "|".join([
            view, domain, name,
            record['ipv4addrs'][0]['ipv4addr'],
            user,
            args.get('change_control')
            ])
        self.logger.info("NEWHOST|%s" % log_msg)

        return host, 201

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
        return { 
                "link": url_for('by_ref', view=view, domain=domain, name=name)
                }, 200

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
