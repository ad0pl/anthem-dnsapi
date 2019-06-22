import requests, json
import re
import logging
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import infoblox.errors

LOG = logging.getLogger(__name__)

class Session():
  requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
  def __init__(self, master="ipam.internal.das", password=None, username=None, ibapauth=None, auth_header=None, default_maximum_objects_returned=None, default_partial_subobjects=None, verify_hostname=False, SSL_ca_path=None, SSL_ca_file=None, SSL_cert_file=None, SSL_key_file=None
):
    """
session = Infoblox.Session(
     "master"   = address,  #Required 
     "username" = string,   #Required  (Option if you pass in ibapauth)
     "password" = string,   #Required 
     "ibapauth" = string,   #Optional ibapauth Cookie from Infoblox for sessions
     "default_maximum_objects_returned"  = num, #Optional, default is to return all matching objects for search operations
     "default_partial_subobjects"  = 0 / 1, #Optional, default is 0 (no partial subobjects for search operations)
     "verify_hostname" = 0 / 1, #Optional. If set to 1 (default), ensures that the hostname of the server will match the hostname in its certificate.
     "SSL_ca_path" = string, #Optional. The path to a directory that contains the Certificate Authority certificates. Ignored unless verify_hostname is 1.
     "SSL_ca_file" = string, #Optional. The path to a file that contains the Certificate Authority certificates. Ignored unless verify_hostname is 1.
     "SSL_cert_file" = string, #Optional, The path to a file that contains the OCSP Client Certificate. SSL_key_file and SSL_cert_file should be defined together.
     "SSL_key_file"  = string, #Optional, The path to a file that contains the OCSP Client Private Key. SSL_key_file and SSL_cert_file should be defined together.
      )
    """
    args = ("master", "password", "username", "default_maximum_objects_returned", "default_partial_subobjects", "verify_hostname", "SSL_ca_path", "SSL_ca_file", "SSL_cert_file", "SSL_key_file")
    values = (master, password, username, default_maximum_objects_returned, default_partial_subobjects, verify_hostname, SSL_ca_path, SSL_ca_file, SSL_cert_file, SSL_key_file)

    self.session    = requests.Session()
    self.apiversion = "v2.7.1"

    # Rather than just a long list of self.field = value we somewhat cheat
    for field, value in zip (args, values):
      setattr(self, field, value)

    self.baseurl    = "https://%s/wapi/%s" % ( self.master, self.apiversion)

    if ibapauth:
      self.session.cookies.set('ibapauth', ibapauth)
    elif auth_header:
        self.session.headers['Authorization'] = auth_header
    else:
      self.session.auth = (self.username, self.password)

    self.session.headers.update({'Accept': 'application/json'})

    if verify_hostname != None:
      self.session.verify = self.verify_hostname

  def _log_request(self, type, url, opts):
    message = ("Sending %s request to %s with parameters %s", type, url, opts)
    LOG.debug(*message)

########################
  def get(self, endpoint, data={}):
    """
Use this method to fetch an object to the Infoblox appliance
TODO: Paging
    """
    requests.packages.urllib3.disable_warnings()
    if not endpoint:
      raise infoblox.errors.InvalidObjectType
    url = "%s/%s" % ( self.baseurl, endpoint)
    self._log_request('get', url, data)
    try:
      if len(data) > 0:
        response = self.session.get(url, params=data)
      else:
        response = self.session.get(url)
      if response.status_code >= 500:
        raise infoblox.errors.ServerError
      if response.status_code >= 401:
        raise infoblox.errors.BadCredentials
      if response.status_code >= 400:
        raise infoblox.errors.BadRequstError
    except Exception as e:
      raise e
    else:
      if re.match(r'^[\[\{]', response.content.decode()):
        # I could check the Content-Type header but I'm not sure if I trust it
        return response.json()
      else:
        return response.content.decode()

  def add(self, endpoint, data={}):
    """
Use this method to add an object to the Infoblox appliance
    """
    if not endpoint:
      raise infoblox.errors.InvalidObjectType
    url = "%s/%s" % ( self.baseurl, endpoint)
    self._log_request('post', url, data)
    try:
      response = self.session.post(url, json=data)
      if response.status_code >= 500:
        raise infoblox.errors.ServerError
      if response.status_code >= 401:
        raise infoblox.errors.BadCredentials
      if response.status_code >= 400:
        raise infoblox.errors.BadRequstError
    except Exception as e:
      raise e
    else:
      if re.match(r'^[\[\{]', response.content.decode()):
        # I could check the Content-Type header but I'm not sure if I trust it
        return response.json()
      else:
        return response.content.decode()

  def delete(self, endpoint):
      """
Use this method to delete an object from Infoblox
      """
      if not endpoint:
          raise infoblox.errors.InvalidObjectType
      url = "%s/%s" % ( self.baseurl, endpoint)
      self._log_request('delete', url, dict())
      try:
          response = self.session.delete(url)
          if response.status_code >= 500:
              raise infoblox.errors.ServerError
          if response.status_code >= 401:
              raise infoblox.errors.BadCredentials
          if response.status_code >= 400:
              raise infoblox.errors.BadRequstError
      except Exception as e:
          raise e
      else:
          if re.match(r'^[\[\{]', response.content.decode()):
              # I could check the Content-Type header but I'm not sure if I trust it
              return response.json()
          else:
              return response.content.decode()

  def update(self, endpoint, data=dict()):
      """
Use this method to update an object from Infoblox
      """
      if not endpoint:
          raise infoblox.errors.InvalidObjectType
      url = "%s/%s" % ( self.baseurl, endpoint)
      self._log_request('update', url, data)
      try:
          response = self.session.put(url, json=data)
          self._log_request('update_response', url, {"status_code": response.status_code, "content": response.content.decode()})
          if response.status_code >= 500:
              raise infoblox.errors.ServerError
          if response.status_code >= 401:
              raise infoblox.errors.BadCredentials
          if response.status_code >= 400:
              raise infoblox.errors.BadRequstError
      except Exception as e:
          raise e
      else:
          if re.match(r'^[\[\{]', response.content.decode()):
              # I could check the Content-Type header but I'm not sure if I trust it
              return response.json()
          else:
              return response.content.decode()
