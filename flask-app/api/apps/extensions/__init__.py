from api.apps.extensions.log import configure_logging
from api.apps.extensions.rest import rest_api, http_status_codes
from api.apps.infoblox.endpoints.register_endpoints import register_infoblox_endpoints

def initialize_extensions(app):
    # Logging
    configure_logging(app)

    # Flask-Restful
    #  We can list as many of the functions that setup the endpoint
    #    routing as we want in the endpoint_registries list
    endpoint_registries = [register_infoblox_endpoints]
    rest_api.init_app(app, endpoint_registries, http_status_codes)

    if app.config['ENV'] == 'production' and app.name != 'test':
        pass

    return app
