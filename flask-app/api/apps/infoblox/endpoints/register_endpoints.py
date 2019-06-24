from api.apps.infoblox.endpoints.resources.record_host import record_host
from api.apps.infoblox.endpoints.resources.record_alias import record_alias
from api.apps.infoblox.endpoints.resources.record_a import record_a
from api.apps.infoblox.endpoints.resources.views import InfobloxViews

def register_infoblox_endpoints(rest_api):
    """
    Registers Flask-Restful Resource class for Infoblox endpoints
    """
    # Views
    rest_api.add_resource(InfobloxViews, "/views")
    # Host Records
    rest_api.add_resource( record_host, "/record_host")
    rest_api.add_resource(
            record_host, 
            "/record_host/<view>/<domain>/<name>", 
            endpoint="by_ref"
    )

    # Alias Records
    rest_api.add_resource( record_alias, "/record_alias")
    rest_api.add_resource(
            record_alias, 
            "/record_alias/<view>/<domain>/<name>", 
            endpoint="alias_by_ref"
    )

    # A Records
    rest_api.add_resource( record_a, "/record_a")
    rest_api.add_resource(
            record_a, 
            "/record_a/<view>/<domain>/<name>", 
            endpoint="a_by_ref"
    )
