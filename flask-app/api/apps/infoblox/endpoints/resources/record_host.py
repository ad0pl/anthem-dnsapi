import logging
from flask import g, current_app, url_for
from flask_restful import Resource, reqparse, abort
from api.apps.extensions.rest import rest_error_response
from infoblox.Session import Session as infoblox_session
import infoblox.errors

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
            _ref = ib.add("record:host", payload).replace('"', '')
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

        record_host_query = {
                'name': "%s.%s" % (name,domain),
                'view': view,
                '_return_fields': "name,comment,view,ipv4addrs,extattrs"
        }
        ib = infoblox_session(master = server, ibapauth = auth_cookie)

        # TODO: At some point of time, this would be easier to do with 
        #   field marshaling but haven't figured it out just yet
        host = { }
        try:
            ret = ib.get("record:host", record_host_query)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        else:
            if len(ret) == 0:
                return rest_error_response(404)
            elif len(ret) == 1:
                name = ret.get('name').replace(".%s" % domain, "")
                host = {
                        'name': name,
                        'domain': domain,
                        'comment': ret.get('comment'),
                        'view': ret.get('view'),
                        'address': ret.get('ipv4addrs')[0].get('ipv4addr'),
                        'link': url_for('by_ref', view=view, domain=domain, name=name)
                        }
            else:
                self.logger.error("more than 1 record for %s" % link)
                return rest_error_response(400)

        return host, 200

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

        # The "new" object can't already exist, so we need to determine
        #   if this is a re-name (new name can't exist) or a re-address
        #   (the new address can't be allocated)
        new_domain = domain.lower() # Domain from the URL path
        new_name   = name.lower()   # hostname from the URL path
        if args.get('domain') != None:
            # They passed the domain in the data
            new_domain = args.get('domain').lower()
        if args.get('name') != None:
            new_name = args.get('name').lower()

        src_fqdn = ("%s.%s" % ( name, domain)).lower()
        new_fqdn = ("%s.%s" % ( new_name, new_domain)).lower()
        new_link = url_for('by_ref', view=view, domain=new_domain, name=new_name)
        if src_fqdn == new_fqdn:
            # The old name and the new name match so it's a re-address oper.
            self.logger.debug("re-address %s => %s" % (new_link, args.get('address')))
            dest_query_type = "record:host_ipv4addr"
            dest_query = {'ipv4addr': args.get('address'),
                    'network_view': "default" 
                    }
        else:
            # The names mis-match so we're just going to assume it's a re-name
            self.logger.debug("re-name %s/%s => %s" % (
                view, src_fqdn, new_fqdn))
            dest_query_type = "record:host"
            dest_query = {'name': new_fqdn, 'view': view}

        ib = infoblox_session(master=server, ibapauth=auth_cookie)
        src_query = {
                'name': src_fqdn, 'view': view,
                '_return_fields': "name,ipv4addrs,extattrs"
                }
        record = None
        try:
            src_resp = ib.get("record:host", src_query)
            dst_resp = ib.get(dest_query_type, dest_query)
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

            # We want an emtpy response for dest_query
            if isinstance(dst_resp, list):
                if len(dst_resp) > 0:
                    msg = "Destination in use"
                    self.logger.error(msg)
                    return rest_error_response(400, detail=msg)
            elif isinstance(dest_rep, dict):
                # we got back just a diction, check if there's a _ref
                #  attribute in the response, that'll tell us if it's empty
                #  or not
                if dst_resp.get('_ref') != None:
                    msg = "Destination in use"
                    self.logger.error(msg)
                    return rest_error_response(400, detail=msg)

        # Destination is clear
        # Check to see if we are permitted to touch the src
        if record.get('extattrs') != None and record['extattrs'].get('Owner') != None and record['extattrs']['Owner']['value'] == "DNSAPI":
            # We are good!
            pass
        else:
            msg = "Object not tagged for modification"
            self.logger.error(msg)
            return rest_error_response(403, detail=msg)

        payload = {
                'name': new_fqdn,
                'view': view,
                'comment': "host updated by API",
                'extattrs': {
                    'Owner': { 'value': "DNSAPI" },
                    'change_number': { 'value': args.get('change_control') }
                    }
                }
        if args.get('address') != None:
            payload['ipv4addrs'] = [ {'ipv4addr': args.get('address') } ]

        try:
            ib.update(record.get('_ref'), payload)
        except Exception as e:
            msg = "Error updating record %s: %s" % (new_fqdn, e.message)
            self.logger.error(msg)
            return rest_error_response(400, detail=msg)

        host = {
                'name': new_name,
                'domain': new_domain,
                'view': view,
                'change_control': args.get('change_control'),
                'address': args.get('address'),
                'link': new_link
                }

        log_msg = "|".join([
            view, domain, name, record['ipv4addrs'][0]['ipv4addr'],
            view, new_domain, new_name,
            "%s" % payload.get('ipv4addrs'), 
            user, args['change_control']
            ])
        self.logger.info("UPDATEHOST|%s" % log_msg)

        return host, 200

    # Delete
    def delete(self, view=None, domain=None, name=None):
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
        payload = {
                'name': "%s.%s" % (name, domain),
                'view': view,
                '_return_fields': 'name,ipv4addrs,extattrs'
                }
        record = None
        try:
            ret = ib.get("record:host", payload)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        except Exception as e:
            self.logger.error("Error logging for record %s/%s/%s: %s" % (
                view, domain, name, str(e)
                ))
            return rest_error_response(500, detail="Unknown Error: %s" % str(e))
        else:
            if isinstance(ret, list):
                if len(ret) > 0:
                    record = ret[0]
                else:
                    # No record was found
                    msg = "%s/%s/%s Not found"
                    self.logger.error(msg)
                    return rest_error_response(404, detail=msg)
            elif isinstance(ret, dict):
                if ret.get('_ref') == None:
                    # No record was found
                    msg = "%s/%s/%s Not found"
                    self.logger.error(msg)
                    return rest_error_response(404, detail=msg)
                else:
                    record = ret
            else:
                msg = "%s/%s/%s Unknown return type: %s" % (
                        view, domain, name, type(ret)
                        )
                self.logger.error(msg)
                return rest_error_response(500, detail=msg)
        # Check to see if we are permitted to delete this
        if record.get('extattrs') != None and record['extattrs'].get('Owner') != None and record['extattrs']['Owner']['value'] == "DNSAPI":
            pass
        else:
            msg = "%s/%s/%s - record not tagged for permission" % (
                    view, domain, name
                    )
            self.logger.error(msg)
            return rest_error_response(403, detail=msg)

        try:
            ib.delete( record.get('_ref') )
        except Exception as e:
            msg = "%s/%s/%s - Error deleting record: %s" % (
                    view, domain, name, str(e)
                    )
            self.logger.error(msg)
            return rest_error_response(500, detail=msg)

        link = url_for('by_ref', view=view, domain=domain, name=name)
        host = {
                'name': name,
                'domain': domain,
                'view': view,
                'comment': record.get('comment'),
                'address' : record.get('ipv4addrs')[0]['ipv4addr'],
                'link': link
                }

        log_msg = "|".join([view,domain,name,user,args['change_control']])
        self.logger.info("DELETEHOST|%s" % log_msg)
        return host, 200
