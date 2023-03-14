'''
Written by Kyle Smith for Aplura, LLC
Copyright (C) 2016-2022 Aplura, ,LLC

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''
from __future__ import absolute_import
import json
import logging
import os
import sys
import time
import urllib

import requests
from aplspl.utilities.kennyloggins import KennyLoggins as KennyLoggins
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import aplspl.version as version

class RestClient:
    """ Base Class for a REST Client """

    @property
    def _session(self):
        return self.__session

    @_session.setter
    def _session(self, x):
        self.__session = x

    @property
    def _use_proxy(self):
        return self.__use_proxy

    @_use_proxy.setter
    def _use_proxy(self, x):
        self.__use_proxy = x

    @property
    def proxies(self):
        return self.__proxies

    @proxies.setter
    def proxies(self, x):
        self.__proxies = x

    @property
    def _splunk_home(self):
        return self.__splunk_home

    @_splunk_home.setter
    def _splunk_home(self, s):
        self.__splunk_home = s

    @property
    def _app_name(self):
        return self.__app_name

    @_app_name.setter
    def _app_name(self, s):
        self.__app_name = s

    _is_debug_mode = False
    _output_type = "json"
    _is_last_url = None
    _token = None
    _verify_certificate = True
    _version = "v1"
    _hostname = None
    _log = None

    class Error(Exception):
        pass

    class ConfigurationError(Exception):
        def __init__(self, expr, msg):
            self.expr = expr
            self.msg = json.dumps(msg)

        def __str__(self):
            return repr(self.msg)

    class HTTPError(Exception):
        def __init__(self, *args, **kwargs):
            response = kwargs.pop('response', None)
            self.response = response
            self.request = kwargs.pop('request', None)
            if response is not None and not self.request and hasattr(response, 'request'):
                self.request = self.response.request
            super(Exception, self).__init__(*args, **kwargs)

    def __init__(self, app_name=None, configuration={}):
        """Construct an instance of the RESTClient"""
        try:
            self._splunk_home = None
            if app_name is None:
                raise Exception("App Name not sent to RESTClient")
            self._app_name = app_name
            if self._splunk_home is None:
                self._splunk_home = make_splunkhome_path([""])
            if self._splunk_home is None:
                raise Exception("SPLUNK HOME UNABLE TO BE SET")
            self._setup_logging()
            self._use_proxy = False
            self._hostname = configuration["hostname"]
        except KeyError as ne:
            self._log.warn("action=failure msg=\"required argument not passed\" argument=\"{}\" ".format(ne))
            raise ValueError("Required argument not passed: {}".format(ne))
        except Exception as e:
            self._catch_error(e)
            raise e

        self._user_agent = "Splunk/ModularInput {} {}".format(self._app_name, version.__version__)
        if configuration["auth"]["type"] == "basic":
            try:
                username = configuration["auth"]["username"]
                password = configuration["auth"]["password"]
            except KeyError as ne:
                self._log.warn("action=failure msg=\"required argument not passed\" argument=\"{}\" ".format(ne))
                raise ValueError("Required argument not passed: {}".format(ne))
            self._session = requests.session()
            self._session.auth = (username, password)
            self._auth_type = "basic"
        if configuration["auth"]["type"] == "token":
            try:
                self._token = configuration["auth"]["token"]
                self._session = requests.session()
                if "authorization_string" not in configuration["auth"]:
                    self._session.headers.update({'Authorization': "Bearer {}".format(configuration["auth"]["token"])})
                else:
                    token = self._token
                    header_auth = {'Authorization': configuration["auth"]["authorization_string"].format(self._token)}
                    #                    self._log.info(header_auth)
                    self._session.headers.update(
                        header_auth)
            except Exception as ne:
                self._log.warn("action=failure msg=\"general exception\" exception=\"{}\" ".format(ne))
                raise ne
        if configuration["auth"]["type"] == "token_url":
            try:
                self._token = configuration["auth"]["token"]
                self._session = requests.session()
            except Exception as ne:
                self._log.warn("action=failure msg=\"general exception\" exception=\"{}\" ".format(ne))
                raise ne
        if "auth" not in configuration:
            self._log.error("Authentication Type not specified")
            raise ValueError("action=failure msg='Authorization Type not specified' ")
        # These are optional parameters
        try:
            self._verify_certificate = True if "verify_certificate" not in configuration else configuration[
                "verify_certificate"]
            self._output_type = "json" if "output_type" not in configuration else configuration["output_type"]
            self._version = None if "version" not in configuration else configuration["version"]
        except:
            pass

        self._session.headers.update({"User-Agent": self._user_agent})
        if "proxy" in configuration:
            self._log.debug("component=proxy found proxy configuration")
            pconfig = configuration["proxy"]

            if "host" not in pconfig or "port" not in pconfig:
                self._log.error(
                    "component=proxy action=get_proxy_config status=failed step='host_or_port'")
                raise AttributeError("Failed to find Hostname or Port in Configuration Object")
            if "useSSL" not in pconfig or not pconfig["useSSL"]:
                protocol = "http"
            else:
                protocol = "https"

            #if "protocol" in pconfig:
            #    protocol = pconfig["protocol"]
            authentication = ""
            hostname = pconfig["host"]
            proxyport = pconfig["port"]
            self._log.debug("component=proxy set hostname={0} and port={1} in proxy configuration".format(hostname,
                                                                                                          proxyport))
            if "authentication" in pconfig:
                self._log.debug("component=proxy found authentication settings")
                authconfig = pconfig["authentication"]
                if "username" not in authconfig or "password" not in authconfig:
                    self.error("component=proxy action=get_proxy_authentication_config status=failed",
                                AttributeError("Failed to find Username or password in Configuration Object"))
                authentication = "{0}:{1}@".format(authconfig["username"], authconfig["password"])
            proxy = {"http": "{0}://{1}{2}:{3}/".format(protocol, authentication, hostname, proxyport),
                     "https": "{0}://{1}{2}:{3}/".format(protocol, authentication, hostname, proxyport)}
            self.proxies = proxy
            self._use_proxy = True

    def _setup_logging(self, ll=logging.INFO):
        kl = KennyLoggins()
        self._log = kl.get_logger(self._app_name, "restclient", ll)

    def _toggle_debug(self):
        if self._is_debug_mode:
            self._is_debug_mode = False
        else:
            self._is_debug_mode = True

    def _format_return(self, obj):
        self._log.debug("output_type = {}".format(self._output_type))
        if self._output_type is "json":
            return json.loads(obj)
        else:
            return obj

    def _read(self, url, payload=None, **kwargs):
        try:
            self._log.debug("starting {} read from url".format(self._version))
            self._is_last_url = url
            # return "I would have returned. But I was delayed."
            r = None
            if payload is not None:
                if "headers" in kwargs:
                    self._log.debug("custom_headers={}".format(kwargs["headers"]))
                    kwargs["headers"]["User-Agent"] = self._user_agent
                    self._session.headers.update(kwargs["headers"])
                else:
                    self._log.debug("no_custom_headers")
                    self._session.headers.update({"Content-Type": "application/x-www-form-urlencoded",
                                                  "Content-Length": len(payload),
                                                  "User-Agent": self._user_agent,
                                                  "Host": self._hostname,
                                                  "Accept-Encoding": "*"
                                                  })
                if not self._use_proxy:
                    self._log.debug("not using the proxy")
                    r = self._session.post(url, verify=self._verify_certificate, data=payload)
                else:
                    self._log.debug("using the proxy")
                    r = self._session.post(url, verify=self._verify_certificate, data=payload, proxies=self.proxies)
            else:
                self._session.headers.update({"User-Agent": self._user_agent})
                if not self._use_proxy:
                    r = self._session.get(url, verify=self._verify_certificate)
                else:
                    r = self._session.get(url, verify=self._verify_certificate, proxies=self.proxies)
            if r.status_code == 200:
                return self._format_return(r.content)
            else:
                self._log.error(
                    " action=read api_version={} status={} content=\"{}\" ".format(self._version, r.status_code, r.content))
                self._raise_for_status(r)
        except Exception as e:
            self._catch_error(e)
            raise e

    def _payload(self, **kwargs):
        return "{}".format(urllib.urlencode(kwargs))

    def _build_url(self):
        self._log.fatal("_build_url not overridden")
        sys.exit(1)

    def _raise_for_status(self, r):
        """Raises stored :class:`HTTPError`, if one occurred."""
        myJson = {}
        try:
            myJson = json.loads(r.content)
        except:
            pass
        additional_info = ""
        if "errors" in myJson:
            if "msg" in myJson["errors"][0]:
                additional_info = myJson["errors"][0]["msg"]
            else:
                additional_info = myJson["errors"][0]
        http_error_msg = ''
        if 400 <= r.status_code < 500:
            http_error_msg = '{} Client Error: reason="{}" url="{}" additional_info="{}"'.format(
                r.status_code, r.reason, r.url, additional_info)
        elif 500 <= r.status_code < 600:
            http_error_msg = '{} Server Error: reason="{}" url="{}" additional_info="{}"'.format(
                r.status_code, r.reason, r.url, additional_info)
        if http_error_msg:
            raise self.HTTPError(http_error_msg, response=r)

    def _catch_error(self, e):
        myJson = {"timestamp": self.gen_date_string(), "log_level": "ERROR"}
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        myJson["errors"] = [{"msg": str(e),
                             "exception_type": "{}".format(type(e)),
                             "exception_arguments": "{}".format(e),
                             "filename": fname,
                             "line": exc_tb.tb_lineno,
                             "hostname": self._hostname
                             }]
        self.error(json.dumps(myJson))

    def gen_date_string(self):
        st = time.localtime()
        tm = time.mktime(st)
        return time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(tm))

    # Public Functions

    def get_last_url(self):
        return self._is_last_url

    def log(self, s):
        self._log.info(s)

    def _build_string(self, o):
        return ' '.join(" {}=\"{}\" ".format(key, val) for (key, val) in o.iteritems())

    def error(self, s, e):
        self._log.error(s)
        if e is None:
            return "Never gonna give you up."
        raise e

    def connect_test(self):
        """Test the Connection to make sure it is up and running"""
        return self._read(self._build_url("", ""))

    def get_version(self):
        return self._version

    def get_token(self):
        return self._token

        # ADD ADDITIONAL METHODS HERE
