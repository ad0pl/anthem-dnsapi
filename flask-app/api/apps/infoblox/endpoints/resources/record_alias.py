import logging
from flask import g, current_app, url_for
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response
from infoblox.Session import Session as infoblox_session
import infoblox.errors

class record_alias(Resource):
    def __init__(self):
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

        super(record_alias, self).__init__()
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
        ib = infoblox_session(master = server, ibapauth=auth_cookie)
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
                "link": url_for('alias_by_ref', view=view, domain=domain, name=name)
                }
        
        log_msg = "|".join([
            view, domain, name,
            record.get('canonical'),
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
        link        =  url_for('alias_by_ref', view=view, domain=domain, name=name)

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
                record = ret[0]
                name = record.get('name').replace(".%s" % domain, "")
                response = {
                        'name': name,
                        'domain': domain,
                        'comment': record.get('comment'),
                        'view': record.get('view'),
                        'canonical': record.get('canonical'),
                        'link': link
                        }
            else:
                self.logger.error("more than 1 record for %s" % link)
                return rest_error_response(400)

        return response, 200

    # Update
    def put(self, view=None, domain=None, name=None):
        args        = self.reqparse.parse_args()
        user        = getattr(g, '_ibuser', None)
        auth_cookie = getattr(g, '_ibapauth', None)
        server      = current_app.config.get('GRID_MASTER')
        link        =  url_for('alias_by_ref', view=view, domain=domain, name=name)

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

        # The "new" object can't already exist, so we need to determine
        #   if this is a re-name (new name can't exist) or a re-targeting
        new_domain = domain.lower() # Domain from the URL path
        new_name   = name.lower()   # hostname from the URL path
        if args.get('domain') != None:
            # They passed the domain in the data
            new_domain = args.get('domain').lower()
        if args.get('name') != None:
            new_name = args.get('name').lower()

        src_fqdn = ("%s.%s" % ( name, domain)).lower()
        new_fqdn = ("%s.%s" % ( new_name, new_domain)).lower()
        new_link = url_for('alias_by_ref', view=view, domain=new_domain, name=new_name)
        if src_fqdn == new_fqdn:
            # The old name and the new name match so it's a re-target oper.
            self.logger.debug("re-target %s => %s" % (new_link, args.get('canonical')))
            # TODO
        else:
            # The names mis-match so we're just going to ass it's a re-naming
            # TODO: We don't need to validate anything about the target
            pass

        ib = infoblox_session(master=server, ibapauth=auth_cookie)
        src_query = {
                'name': src_fqdn, 'view': view,
                '_return_fields': "name,canonical,extattrs"
                }
        record = None
        try:
            src_resp = ib.get("record:cname", src_query)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        except Exception as e:
            self.logger.error("Unknown error looking for existing records: %s" % str(e))
            return rest_error_response(500, detail="Unknown error: %s" % str(e))
        else:
            # If we get an empty response for src_query throw a NOTFOUND error
            if isinstance(src_resp, list):
                if len(src_resp) > 0:
                    record = src_resp[0]
                else:
                    # No records were found
                    self.logger.error("Modify can't find src object: %s/%s" % (view, src_fqdn))
                    return rest_error_response(404, detail="%s/%s%s not found" % (view,domain,name))
            elif isinstance(src_resp, dict) and src_resp.get('_ref') != None:
                record = src_resp
            else:
                return rest_error_response(400, detail="Unknown return type")



    # Delete
    def put(self, view=None, domain=None, name=None):
        pass
