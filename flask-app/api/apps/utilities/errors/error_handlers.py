from flask import current_app

from api.apps.utilities.endpoints.req_resp import json_api_error, json_api_resp


def unauthorized(e):
    """
    HTTP 401 exception handler.
    Argument:
        e (Exception)
    Return:
        resp_json (str): JSON API formatted error response payload
    """

    current_app.logger.error('HTTP 401 - {}'.format(e.message))

    # JSON API error response format helper.
    resp_json = json_api_error('401', 'Unauthorized')

    return json_api_resp(resp_json, 401)


def forbidden(e):
    """
    HTTP 403 exception handler.
    Argument:
        e (Exception)
    Return:
        resp_json (str): JSON API formatted error response payload
    """

    current_app.logger.error('HTTP 403 - {}'.format(e.message))

    # JSON API error response format helper.
    resp_json = json_api_error('403', 'Forbidden')

    return json_api_resp(resp_json, 403)


def page_not_found(e):
    """
    HTTP 404 exception handler.
    Argument:
        e (Exception)
    Return:
        resp_json (str): JSON API formatted error response payload
    """

    current_app.logger.error('HTTP 404 - {}'.format(e.message))

    # JSON API error response format helper.
    resp_json = json_api_error('404', 'Not Found')

    return json_api_resp(resp_json, 404)


def tea_pot(e):
    """
    HTTP 418 exception handler. Happy Easter!
    Argument:
        e (Exception)
    Return:
        resp_json (str): JSON API formatted error response payload
    """

    current_app.logger.error('HTTP 418 - {}'.format(e.message))

    # JSON API error response format helper.
    resp_json = json_api_error('418', 'This server is a teapot, not a coffee machine')

    return json_api_resp(resp_json, 418)


def internal_server_error(e):
    """
    HTTP 500 exception handler
    Argument:
        e (Exception)
    Return:
        resp_json (str): JSON API formatted error response payload
    """

    current_app.logger.error('HTTP 500 - {}'.format(e.message))

    # JSON API error response format helper.
    resp_json = json_api_error('500', 'Internal Server Error')

    return json_api_resp(resp_json, 500)


def register_error_handlers(app):
    """
    Registers error handlers on Flask application.
    Argument:
        app (Flask)
    Return:
        (None)
    """

    app.register_error_handler(401, unauthorized)
    app.register_error_handler(403, forbidden)
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(418, tea_pot)
    app.register_error_handler(500, internal_server_error)
    app.register_error_handler(Exception, internal_server_error)
