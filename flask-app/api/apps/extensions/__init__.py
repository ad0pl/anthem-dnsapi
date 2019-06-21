from api.apps.extensions.log import configure_logging
#from api.apps.extensions.rest import rest_api, http_status_codes

def initialize_extensions(app):
    # Logging
    configure_logging(app)

    if app.config['ENV'] == 'production' and app.name != 'test':
        # Flask-SSLify
        #from api.apps.extensions.ssl import SSLify
        #SSLify(app)
        pass

    return app
