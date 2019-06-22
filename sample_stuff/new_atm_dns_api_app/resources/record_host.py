import json
import logging
from flask import abort
from flask_restful import Resource, reqparse, fields, marshal_with

from new_atm_dns_api_app.globals import GLOBALS
from new_atm_dns_api_app.infoblox.Session import Session as infoblox_session
import new_atm_dns_api_app.infoblox.errors

#########
# Ignore this for now
#########
record_host_fields = {
        'fqdn': fields.String,
        'address': fields.String,
        'comment': fields.String,
        'disable': fields.Boolean,
        'view': fields.String,
        'link': fields.Url('by_ref', absolute=False)
        }

class record_host_object(object):
    __slots__ = ['name', 'domain', 'address', 'comment', 'disable', 'extattrs', 'view', 'link']
    def __init__(self, **kwargs):
        # Has the side effect of ignoring bad keywords
        for fieldName in self.__slots__:
            setattr(self, fieldName, kwargs.get(fieldName))
    def __str__(self):
        ret = {slot: getattr(self, slot) for slot in self.__slots__}
        return "%s" % ret
    def as_json(self):
        ret = {slot: getattr(self, slot) for slot in self.__slots__}
        return json.dumps(ret)
    def as_host(self):
        return {
                "name"   : self.name,
                "domain" : self.domain,
                "address": self.address,
                "view"   : self.view,
                "link"   : None
                }
    def as_infoblox(self):
        return {
                'name': "%s.%s" % (self.name, self.domain),
                'ipv4addrs': [ { 'ipv4addr': self.address } ],
                'extattrs': {
                    'Owner': { 'value': "DNSAPI" }
                    }
                }
#########
# End of Ignore section
#########


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
        self.logger.debug("post", {"user": GLOBALS['user'], "link": "%s/%s/%s" % ( args.get('view'), args.get('domain'), args.get('name'))})

        domain = GLOBALS['default_domain']
        if args.get('domain') != None:
            domain = args['domain']
        fqdn = ("%s.%s" % (args['name'], domain)).lower()
        view = args['view']

        payload = {
                'name': fqdn,
                'view': view,
                'comment': "host created by API at some time",
                'ipv4addrs': [ { 'ipv4addr': args['address'] } ],
                'extattrs': {
                    'Owner': { "value": "DNSAPI" },
                    'change_number': { "value": args['change_control'] },
                }
        }
        ib = infoblox_session ( master = GLOBALS['grid_master'], ibapauth = GLOBALS['ibapauth'] )
        record_host = []
        record_addr = []
        # Check to see if the hostname is already in use or
        #   if the address is already allocated
        try:
            # The hostname can't be used anywhere
            record_host = ib.get("record:host", {'name': fqdn, 'view': view})
            record_addr = ib.get("record:host_ipv4addr", {'ipv4addr': args['address'], 'network_view': "default"})
        except new_atm_dns_api_app.infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials", {"user": GLOBALS['user'], "payload": payload})
            abort(403)
        except Exception as e:
            self.logger.error("existing allocation: %s" % str(e), {"user": GLOBALS['user'], "payload": payload})
            abort(400)

        if len(record_host) > 0:
            self.logger.error ("%s/%s - DNS Record in use" % (view,fqdn))
            abort(400)
        # The IP Address can't be already used
        if len(record_addr) > 0:
            self.logger.error ("%s/%s - Address (%s) in use" % (view,fqdn,args['address']))
            abort(400)

        record = None
        try:
            # We should get a reference to the object but it might be surrounded by quotes
            _ref = ib.add("record:host", payload).replace('"','')
            ret = ib.get(_ref, {"_return_fields": "name,comment,ipv4addrs,disable,view,extattrs"})
        except new_atm_dns_api_app.infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials:add", {"user": GLOBALS['user'], "payload": payload})
            abort(403)
        except Exception as e:
            self.logger.error("%s/%s - Error adding new allocation: %s" % (view,fqdn,str(e)))
            abort(400)
        else:
            if type(ret) == type(list()):
                if len(ret) > 0:
                    record = ret[0]
                else:
                    # No records were found
                    self.logger.error("%s/%s - Should never get here: %s" % (view,fqdn,str(e)))
                    abort(404)
            elif type(ret) == type(dict()) and ret.get('_ref'):
                record = ret
            else:
                self.logger.error("%s/%s - invalid response from Infoblox: %s" % (view,fqdn,ret))
                abort(500)


        name = record['name'].replace(".%s" % domain,"")
        host = {
                'name'    : name,
                'domain'  : domain,
                'comment' : record.get('comment'),
                'address' : record['ipv4addrs'][0]['ipv4addr'],
                'disable' : record['disable'],
                'view'    : record['view'],
                'link'    : "/api/v0.1/record_host/%s/%s/%s" % ( view, domain, name )
        }

        log_msg = "|".join([view,domain,name,record['ipv4addrs'][0]['ipv4addr'],GLOBALS['user'],args['change_control']])
        self.logger.info("NEW HOST|%s" % log_msg)

        return host, 201

    # Read/Retreive
    def get(self, view=None, domain=None, name=None):
        self.logger.debug("get", {"user": GLOBALS['user'], "link": "%s/%s/%s" % ( view, domain, name)})
        payload = {
                'name': None,
                'view': None
                }

        if view == None or domain == None or name==None:
            # Not even sure how it got here if either are empty
            abort(400)

        payload['view'] = view
        payload['name'] = "%s.%s" % (name, domain)
        payload['_return_fields'] = ",".join(["name","comment","view","zone","ipv4addrs","extattrs","disable"])

        #print(GLOBALS['ibapauth'])
        ib = infoblox_session (
            master = GLOBALS['grid_master'], ibapauth = GLOBALS['ibapauth']
                    )
        # Supposely this is a lot easier with field marshaling but I can't seem to get it to work
        try:
            ret = ib.get("record:host", payload)
            if len(ret) == 0:
                abort(404)
            elif len(ret) == 1:
                ret_name = ret['name'].replace(".%s" % domain,"")
                host = {
                        'fqdn'    : ret_name,
                        'domain'  : domain,
                        'comment' : ret[0].get('comment'),
                        'address' : ret[0]['ipv4addrs'][0]['ipv4addr'],
                        'disable' : ret[0]['disable'],
                        'view'    : ret[0]['view'],
                        'link'    : "/api/v0.1/record_host/%s/%s/%s" % ( view, domain, name )
                        }
            else:
                #  There should only be 1 record, more than one says something is off
                abort(400)
        except new_atm_dns_api_app.infoblox.errors.BadCredentials:
            abort(403)

        return host

    # Update
    def put(self, view=None, domain=None, name=None):
        args = self.reqparse.parse_args()
        self.logger.debug("put", {"user": GLOBALS['user'], "link": "%s/%s/%s" % ( view, domain, name)})

        if view == None or domain == None or name==None:
            # Not even sure how it got here if either are empty
            abort(400)

        # Requirement #1 - views MUST be the same
        new_view = view
        if args.get('view') != None:
            new_view = args.get('view')
        if view != new_view:
            self.logger.error("Views must match (%s / %s" % ( view, new_view ))
            abort(400)

        # Is this a re-name operation or a re-address operation
        #    The destination shouldn't exist so do we query
        #    for a new address or a new host name
        new_domain = domain.lower()
        new_name = name.lower()
        if args.get('domain') != None:
            new_domain = args.get('domain').lower()
        if args.get('name') != None:
            new_name = args.get('name').lower()

        src_fqdn = ("%s.%s" % (name, domain)).lower()
        new_fqdn = ("%s.%s" % (new_name, new_domain)).lower()
        if src_fqdn == new_fqdn:
            # Old name == New name so it should be a re-address operation
            self.logger.debug("re-address (%s/%s)" % (view, new_fqdn), {"new_addr": args.get('address')})
            dest_query_type = "record:host_ipv4addr"
            dest_query = { 'ipv4addr': args['address'], 
                'network_view': "default"
            }
        else:
            # Names mis-match so it should be a host rename operation
            self.logger.debug("re-name (%s/%s)" % (view, src_fqdn), {"new_link": "%s/%s" % (view, new_fqdn)})
            dest_query_type = "record:host"
            dest_query = { 'name': new_fqdn, 'view': view }

        ib = infoblox_session (
            master = GLOBALS['grid_master'], ibapauth = GLOBALS['ibapauth']
        )
        src_query = {
                'name': "%s.%s" % (name, domain),
                'view': view,
                '_return_fields': 'name,ipv4addrs,extattrs'
        }
        record = None
        try:
            src_resp = ib.get("record:host", src_query)
            dst_resp = ib.get(dest_query_type, dest_query)
        except new_atm_dns_api_app.infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials", {"user": GLOBALS['user'], "payload": payload})
            abort(403)
        except Exception as e:
            self.logger.error("Error looking for record: %s" % str(e))
            abort(400)
        else:
            # If we get an empty response for src_query throw a NOTFOUND error
            if type(src_resp) == type(list()):
                if len(src_resp) > 0:
                    record = src_resp[0]
                else:
                    # No records were found
                    self.logger.error("Source not found")
                    abort(404)
            elif type(src_resp) == type(dict()) and src_resp.get('_ref'):
                record = src_resp
            else:
                abort(400)

            # We want an empty response for dest_query
            if type(dst_resp) == type(list()):
                if len(dst_resp) > 0:
                    self.logger.error("Destination in use")
                    abort(400)
            elif type(dst_resp) == type(dict()):
                if dst_resp.get('_ref') != None:
                    self.logger.error("Destination in use")
                    abort(400)

        # Check to see if we're permitted to delete this
        if record.get('extattrs') != None and record['extattrs'].get('Owner') != None and record['extattrs']['Owner']['value'] == "DNSAPI":
            pass
        else:
            self.logger.error("Source not tagged as updatable")
            abort(403)

        payload = {
                'name': new_fqdn,
                'view': view,
                'comment': "host updated by API at some time",
                'extattrs': {
                    'Owner': { "value": "DNSAPI" },
                    'change_number': { "value": args['change_control'] }
                }
        }
        if args.get('address') != None:
            payload['ipv4addrs'] = [ { 'ipv4addr': args.get('address') } ]

        try:
            ib.update(record['_ref'], payload)
        except Exception as e:
            self.logger.error("Error Updating record: %s" % str(e))
            abort(400)

        host = {
                'name': new_name,
                'domain': new_domain,
                'view': view,
                'change_control': args.get('change_control'),
                'address': args.get('address')
                }

        log_msg = "|".join([view,domain,name,record['ipv4addrs'][0]['ipv4addr'],new_view,new_domain,new_name,"%s" % payload.get('ipv4addrs'), GLOBALS['user'],args['change_control']])
        self.logger.info("UPDATE HOST|%s" % log_msg)
        return host, 200

    # Destroy
    def delete(self, view=None, domain=None, name=None):
        self.logger.debug("delete", {"user": GLOBALS['user'], "link": "%s/%s/%s" % ( view, domain, name)})
        args = self.delparse.parse_args()

        if view == None or domain == None or name==None or args.get('change_control') == None:
            # Not even sure how it got here if either are empty
            self.logger.error("One of required fields is missing: %s" % str({"view": view, "domain": domain, "name": name, "change_control": args.get('change_control')}))
            abort(400)

        # Search Infoblox for the record to delete
        ib = infoblox_session (
            master = GLOBALS['grid_master'], ibapauth = GLOBALS['ibapauth']
        )
        payload = {
                'name': "%s.%s" % (name, domain),
                'view': view,
                '_return_fields': 'name,ipv4addrs,extattrs'
                }
        try:
            ret = ib.get("record:host", payload)
        except new_atm_dns_api_app.infoblox.errors.BadCredentials:
            self.logger.error("BadCredentials", {"user": GLOBALS['user'], "payload": payload})
            abort(403)
        except Exception as e:
            self.logger.error("Error looking for record: %s" % str(e))
            abort(400)
        else:
            # An empty response is still valid from infoblox
            #   but we will want to throw a NOTFOUND error
            record = None
            if type(ret) == type(list()):
                if len(ret) > 0:
                    record = ret[0]
                else:
                    # No records were found
                    self.logger.error("Record Not Found", {"user": GLOBALS['user'], "payload": payload})
                    abort(404)
            elif type(ret) == type(dict()) and ret.get('_ref'):
                record = ret
            else:
                self.logger.error("Unknown record type returned", {"user": GLOBALS['user'], "ret": ret})
                abort(400)

        # Check to see if we're permitted to delete this
        if record.get('extattrs') != None and record['extattrs'].get('Owner') != None and record['extattrs']['Owner']['value'] == "DNSAPI":
            pass
        else:
            self.logger.error("Record not tagged as updatable")
            abort(403)

        try:
            _ref = record['_ref']
            ib.delete(_ref)
        except Exception as e:
            self.logger.error("Error deleting record: %s" % str(e))
            abort(400)
        else:
            # Create a Host Record to show what we deleted
            host = {
                    'name'    : name,
                    'domain'  : domain,
                    'view'    : view,
                    'comment' : record.get('comment'),
                    'address' : record.get('ipv4addrs')[0]['ipv4addr'],
                    'link'    : "/api/v0.1/record_host/%s/%s/%s" % ( view, domain, name )
            }


        log_msg = "|".join([view,domain,name,GLOBALS['user'],args['change_control']])
        self.logger.info("DELETE HOST|%s" % log_msg)
        return host, 200
