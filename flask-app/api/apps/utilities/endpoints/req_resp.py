import json
from functools import wraps

from flask import make_response, request, current_app
from flask_restful import reqparse, abort


def json_api_error(status, title, detail=None, source=None, restful_error=None):
    """
    Creates JSON API specification error response payload
    Arguments:
        status (str): HTTP status code
        title (str): Error message content
    Key Word Arguments:
        detail (str): Title detail content
        source (dict): Pointer to endpoint returning error
        restful_error (bool): Determine if error response handled by Flask application of Flask-Resful API
    Return:
        error_resp (str) if not restful_error, else (dict)
    """

    error = {
        'status': status,
        'title': title
    }

    if source:
        error.update({'source': source})
    if detail:
        error.update({'detail': detail})

    error_resp = {'errors': [error]}

    # If error raised by Flask-Restful endpoint, format response accordingly.
    if not restful_error:
        error_resp = json.dumps({'message': error_resp})

    return error_resp

def json_api_not_found_resp():
    """
    Personal interpretation on JSON API specification response for no records found.
    Return:
        (Flask Response)
    """

    not_found_json = json.dumps({"data": {"message": "resources not found"}})

    return json_api_resp(not_found_json)

def json_api_success(message=None):
    """
    Personal interpretation on JSON API specification response for successfully received and queued payload for
    processing by worker.
    Return:
        (Flask Response)
    """
    if message:
        json_message = message
    else:
        json_message = "success"

    success_json = json.dumps({"data": {"message": json_message}})

    return json_api_resp(success_json)


