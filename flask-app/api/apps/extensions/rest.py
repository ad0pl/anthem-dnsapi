from flask_restful import Api

error_codes = {
        400: "Client error",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not found",
        415: "Unsupported Media Type",
        418: "Not a Tea Pot",
        422: "Improper JSON",
        500: "Internal Server Error"
        }

def rest_error_response(code, detail=None, source=None):
    if error_codes.get(code) == None:
        code = 500

    response = {
            "message": {
                "errors": [
                    { 
                        "status": code,
                        "title" : error_codes[code]
                    }
                ]
            }
    }
    if detail != None:
        response['message']['errors'][0]['detail'] = detail
    if source != None:
        response['message']['errors'][0]['source'] = source
    return response, code

class FlaskRestApi(object):
    """
    Utility to mimic Flask Extension.init_app pattern while configuring customer error messages.
    """

    def __init__(self):
        self.api = Api

    def init_app(self, app, endpoint_registries):
        """
        Initializes Flask-Restful API class with Flask application context, configures custom error messages
        and registers API endpoints.
        Arguments:
             app (Flask instace)
             endpoint_registries (list): functions to register Resource endpoints on Api instance
        Return:
            None
        """

        # Initialize Flask-Restful instance with 
        #   Flask application context and custom errors.
        prefix = "/api/%s" % app.config['APP_VERSION']
        app.logger.debug("App Prefix: %s" % prefix)
        rest_api = self.api(app, prefix=prefix)

        [endpoint_registry(rest_api) for endpoint_registry in endpoint_registries]

rest_api = FlaskRestApi()
