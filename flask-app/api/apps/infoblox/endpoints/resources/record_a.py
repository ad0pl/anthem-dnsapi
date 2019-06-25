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
        self.reqparse.add_argument('addresses', type = list, required = True,
                help = 'No addresses provided', location = 'json')
        self.reqparse.add_argument('change_control', type = str, required = True,
                help = 'No change_control provided', location = 'json')
        self.reqparse.add_argument('domain', type = str, location = 'json')

        # Delete only really requires that we have change control
        self.delparse = reqparse.RequestParser()
        self.delparse.add_argument('change_control', type = str, required = True,
                help = 'No change_control provided', location = 'json')

        super(record_a, self).__init__()
        self.logger = logging.getLogger(__name__)

    # Create
    def post(self):
        args = self.reqparse.parse_args()
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = current_app.config.get('GRID_MASTER')
        domain      = current_app.config.get('DEFAULT_DOMAIN')

        self.logger.debug("method=post,user=%s,link=%s/%s/%s" % (
            user, args.get('view'), args.get('domain'), args.get('name')
                ))
        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        if args.get('domain') != None:
            domain = args.get('domain')

        link        =  url_for('a_by_ref', 
            view=args.get('view'), domain=domain, name=args.get('name')
        )

        fqdn = ("%s.%s" % ( args.get('name'), domain)).lower()
        view = args.get('view')

        template = {
                'name': fqdn,
                'view': view,
                'comment': "DNS A record created by API",
                'extattrs': {
                    'Owner': { 'value': "DNSAPI" },
                    'change_number': { "value": args.get('change_control') },
                    }
                }
        ib = infoblox_session(master = server, ibapauth=auth_cookie)

        # Check to make sure there's no existing records
        #   We're not going to check the IP address just the hostname
        #     we could be adding the records to give an address another name and
        #     can't use aliases
        try:
          exist_record = ib.get("record:a", { "name": fqdn, 'view': view })
        except infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials")
            return rest_error_response(401)
        except Exception as e:
            return rest_error_response(500, detail="Something happened during checking existing: %s" % str(e) )
        else:
            if len(exist_record) > 0:
                msg = "%s/%s - DNS Record in use" % (view,fqdn)
                self.logger.error(msg)
                return rest_error_response(400, detail=msg)

        # look through all the addresses, we need to add them separately
        ref_list = []
        for addr in args.get('addresses'):
            payload = template.copy()
            payload['ipv4addr'] = addr
            try:
                _ref = ib.add("record:a", payload)
                ref_list.append(_ref)
                self.logger.debug("added: %s" % _ref)
            except infoblox.errors.BadCredentials:
                self.logger.error("BadCredentials")
                return rest_error_response(401)
            except Exception as e:
                return rest_error_response(500, detail="Something happened during adding new: %s" % str(e) )

        # We construct our successful response back to the client
        # Use the response back from infoblox but remove out the domain
        #  TODO: re-query the record to make sure it got in okay and build the response from that
        #name = record.get('name').replace(".%s" % domain, "")
        name = fqdn.replace(".%s" % domain, "")
        response = {
                'name': name,
                'domain': domain,
                'comment': "DNS A record created by API",
                'addresses': args.get('addresses'),
                'view': view,
                "link": url_for('a_by_ref', view=view, domain=domain, name=name)
                }

        log_msg = "|".join([
            view, domain, name,
            str(args.get('addresses')),
            user,
            args.get('change_control')
            ])
        self.logger.info("NEWA|%s" % log_msg)

        return response, 201

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

        record_a_query = {
                'name': "%s.%s" % (name,domain),
                'view': view,
                '_return_fields': "name,comment,view,ipv4addr,extattrs"
        }
        ib = infoblox_session(master = server, ibapauth = auth_cookie)
        response = { }
        try:
            ret = ib.get("record:a", record_a_query)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        else:
            if len(ret) == 0:
                return rest_error_response(404, detail="DNS Record not found")
            response = {
                'name': name,
                'domain': domain,
                'view': view,
                'comment': ret[0].get('comment'),
                'link': link
            }
            addresses = []
            for record in ret:
                addresses.append(record.get('ipv4addr'))
            response['addresses'] = addresses


        return response, 200

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

        # Check to see if this is a rename operation
        src_name = ("%s.%s" % ( name, domain )).lower()
        dst_name = ("%s.%s" % ( args.get('name'), args.get('domain') )).lower()
        if src_name != dst_name:
            # Re-name operation, We need to check to make sure there's nothing at the dest name
            try:
                dst_check = ib.get("record:a", { 'view': view, 'name': dst_name })
            except Exception as e:
                msg = "Error checking to see if new name exists:%s:%s" % ( dst_name, str(e) )
            else:
                if len(dst_check) > 0:
                    msg = "New Name already exists: %s" % dst_name
                    self.logger.error(msg)
                    return rest_error_response(400, detail=msg)
        # The Modify is going to be a delete and add operation, so delete out the old
        #    and add in the new
        # Fetch existing
        try:
            existing_records = ib.get("record:a", { 'view': view, 'name': src_name })
        except Exception as e:
            msg = "Error  new name exists check:%s:%s" % (src_name, str(e))
            self.logger.error(msg)
            return rest_error_response(400, msg)
        else:
            if len(existing_records) == 0:
                msg = "Error  new name exists:%s:%s" % (src_name, str(e))
                self.logger.error(msg)
                return rest_error_response(400, msg)

        # Delete existing
        try:
            for record in existing_records:
                ib.delete(record.get('_ref'))
        except Exception as e:
            msg = "Error deleting record:%s:%s" % (src_name, str(e))
            self.logger.error(msg)
            return rest_error_response(400, msg)
        
        # Create New Records
        # FIXME
 

        return rest_response_error(400, detail="TODO: Method not complete yet")

    # Delete
    def delete(self, view=None, domain=None, name=None):
        args = self.delparse.parse_args()
        auth_cookie = getattr(g, '_ibapauth', None)
        user        = getattr(g, '_ibuser', None)
        server      = current_app.config.get('GRID_MASTER')
        link        =  url_for('a_by_ref', view=view, domain=domain, name=name)

        self.logger.debug("method=delete,user=%s,link=%s/%s/%s" % (
            user, view, domain, name
        ))

        if auth_cookie == None:
            # User wasn't authenicated or another error happened
            return rest_error_response(401)

        record_a_query = {
                'name': "%s.%s" % (name,domain),
                'view': view,
                '_return_fields': "name,comment,view,ipv4addr,extattrs"
        }
        ib = infoblox_session(master=server, ibapauth=auth_cookie)

        # Retrieve all the existing Infoblox objects
        #   While we're at it, we'll construct our response
        response = {
            'name': name,
            'domain': domain,
            'view': view,
            'link': link
        }
        ref_to_delete = []
        ref_to_nottouch = []
        try:
            ret = ib.get("record:a", record_a_query)
        except infoblox.errors.BadCredentials:
            return rest_error_response(403)
        else:
            if len(ret) == 0:
                return rest_error_response(404, detail="DNS Record not found")
            addresses = []
            response['comment'] = ret[0].get('comment')
            for record in ret:
                # Since there's multiple records for A records
                #   Validate each one seperately
                if record.get('extattrs') != None and record['extattrs'].get('Owner') != None and record['extattrs']['Owner']['value'] == "DNSAPI":
                    addresses.append(record.get('ipv4addr'))
                    ref_to_delete.append  ( [ record.get('_ref'), record.get('ipv4addr') ] )
                else:
                    ref_to_nottouch.append( [ record.get('_ref'), record.get('ipv4addr') ] )
            response['addresses'] = addresses

        if len(ref_to_delete) < 1:
            msg = "%s/%s/%s - record not tagged for permission" % (
                    view, domain, name
                    )
            self.logger.error(msg)
            return rest_error_response(403, detail=msg)

        # Log for troubleshooting purposes if one of the records is not updatable
        if len(ref_to_nottouch) > 0:
            msg = "Error: The following records were marked as not updatble by the API: %s" % ( str(ref_to_nottouch) )
            self.logger.error(msg)

        # Delete the records
        for ref in ref_to_delete:
            try:
                ib.delete( ref[0] )
            except Exception as e:
                msg = "%s/%s/%s (%s) - Error deleting record: %s" % (
                        view, domain, name, ref[1], str(e)
                        )
                self.logger.error(msg)
                return rest_error_response(500, detail=msg)

        return response,200
