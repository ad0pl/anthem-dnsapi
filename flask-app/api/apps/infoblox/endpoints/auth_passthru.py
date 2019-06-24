import logging
from flask import g, current_app, request, abort
#from flask_restful import abort
from infoblox.Session import Session as infoblox_session
import infoblox.errors
import re

logger = logging.getLogger(__name__)

def infoblox_auth_prereq():
    """
    We look for the infoblox token as a cookie or that they passed an 
      Authorization header, and use them to connect to the Infoblox
      Grid.  As long as either of them works, the Grid will return back
      a cookie to use as a token for later requests.  Pass that back
      to the user as our own cookie
    """
    auth_cookie = request.cookies.get('ibapauth')
    auth_header = request.headers.get('Authorization')
    server      = current_app.config.get('GRID_MASTER')
    ib = None

    if auth_cookie == None and auth_header == None:
        # No Infoblox token or Auth header
        logger.debug("No Auth")

    # If they have a cookie try that first before attempting
    #   the Auth header, it's MUCH faster
    if auth_cookie != None:
        ib = infoblox_session ( master = server, ipauth = auth_cookie )
        try:
            logger.debug("Attemping using a cookie")
            ib.get("?_schema")
        except infoblox.errors.BadCredentials:
            ib = None
        except Exception as e:
            logger.error("Something bad happene: %s" % e.message)
            #abort(500)

    # If the cookie wasn't there or didn't work, try the auth header
    #    if it exists
    if ib == None and auth_header != None:
        ib = infoblox_session ( master = server, auth_header = auth_header )
        try:
            logger.debug("Attemping using a Auth header")
            ib.get("?_schema")
        except:
            pass

    if ib != None and ib.session.cookies.get('ibapauth') != None:
        auth_cookie = ib.session.cookies.get('ibapauth')
        user = re.search(r'user=\w+', auth_cookie).group(0).split("=")[1]

        setattr(g, '_ibapauth', auth_cookie)
        setattr(g, '_ibuser', user)

        logger.info("Login: user=%s" % user)
    if ib != None and ib.session.cookies.get('ibapauth') == None:
        # Somehow Infoblox didn't return a working cookie for later
        #  We need to error out
        #abort(500)
        logger.error("Infoblox didn't return an auth cookie")
        pass
    else:
        logger.debug("No Auth2")


def infoblox_auth_postreq(response):
    """
    Forget about the cookie and their username.
    """
    cookie = getattr(g, '_ibapauth', None)
    if cookie != None:
        response.set_cookie('ibapauth', cookie)
    setattr(g, '_ibapauth', None)
    setattr(g, '_ibuser', None)
    return response
