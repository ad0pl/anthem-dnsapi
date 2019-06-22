from api.apps.infoblox.endpoints.resources.record_host import record_host

def register_infoblox_endpoints(rest_api):
    """
    Registers Flask-Restful Resource class for Infoblox endpoints
    """
    rest_api.add_resource(
            record_host, 
            "/record_host"
    )
    rest_api.add_resource(
            record_host, 
            "/record_host/<view>/<domain>/<name>", 
            endpoint="by_ref"
    )