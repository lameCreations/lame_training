"""
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
"""
from __future__ import absolute_import
import sys
import os.path
if sys.version_info >= (3, 0):
    base_location = sys.path[0].split(os.path.sep)
    base_location.pop(-1)
    bl = os.path.sep.join(base_location)
    sys.path.insert(0, os.path.sep.join([bl, "lib", "python3.7", "site-packages"]))
    sys.path.insert(0, os.path.sep.join([bl, "bin", "lib", "python3.7", "site-packages"]))
    sys.path.insert(0, os.path.sep.join([bl, "bin"]))

import csv
import json
import logging
import os
import sys
import re
from logging import handlers
import splunk
import splunk.entity as entity
import splunk.rest as rest
from splunk.appserver.mrsparkle.lib.util import get_apps_dir
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import version


class KennyLoggins:
    """ Base Class for Logging """

    def __init__(self, **kwargs):
        """Construct an instance of the Logging Object"""

    def get_logger(self, app_name=None, file_name="kenny_loggins", log_level=logging.INFO):
        log_location = make_splunkhome_path(['var', 'log', 'splunk', app_name])
        # logging.setLoggerClass(SplunkLogger)
        useLogCFG = True
        LOGGING_DEFAULT_CONFIG_FILE = make_splunkhome_path(['etc', 'apps', app_name, 'default', 'log.cfg'])
        LOGGING_LOCAL_CONFIG_FILE = make_splunkhome_path(['etc', 'apps', app_name, 'local', 'log.cfg'])
        LOGGING_DEFAULT_CONFIG_FILE_CONF = make_splunkhome_path(
            ['etc', 'apps', app_name, 'default', 'apl_logging.conf'])
        LOGGING_LOCAL_CONFIG_FILE_CONF = make_splunkhome_path(['etc', 'apps', app_name, 'local', 'apl_logging.conf'])
        LOGGING_STANZA_NAME = app_name
        _log = logging.getLogger("{}".format(file_name))
        if not os.path.isdir(log_location):
            os.mkdir(log_location)
        if os.path.isfile(LOGGING_DEFAULT_CONFIG_FILE_CONF) or os.path.isfile(LOGGING_LOCAL_CONFIG_FILE_CONF):
            useLogCFG = False
        output_file_name = os.path.join(log_location, "{}.log".format(file_name))
        _log.propogate = False
        _log.setLevel(log_level)
        f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
        formatter = logging.Formatter(
            '%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s file="%(filename)s" function="%(funcName)s" line_number="%(lineno)d" version="{}" %(message)s'.format(
                version.__version__))
        f_handle.setFormatter(formatter)
        if not len(_log.handlers):
            _log.addHandler(f_handle)
        try:
            if not useLogCFG:
                _log.info("action=setting_levels source=apl_logging.conf local='{}' default='{}'".format(
                    LOGGING_LOCAL_CONFIG_FILE_CONF, LOGGING_DEFAULT_CONFIG_FILE_CONF
                ))
                splunk.setupSplunkLogger(_log, LOGGING_DEFAULT_CONFIG_FILE_CONF, LOGGING_LOCAL_CONFIG_FILE_CONF,
                                         LOGGING_STANZA_NAME)
            else:
                _log.info("action=setting_levels source=log.cfg local='{}' default='{}'".format(
                    LOGGING_LOCAL_CONFIG_FILE, LOGGING_DEFAULT_CONFIG_FILE
                ))
                splunk.setupSplunkLogger(_log, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE,
                                         LOGGING_STANZA_NAME)
        except Exception as e:
            _log.setLevel(logging.DEBUG)
            _log.error("Failed to setup Logger {3}:{4}: {1}:{0}, setting log_level to {2}".format(e, type(e), log_level,
                                                                                                  app_name, file_name))
            _log.setLevel(log_level)
        return _log

class Thanos:
    def __init__(self, **kwargs):
        """Construct an instance of the Thanos Object"""
        self.session_key = kwargs.get("session_key")
        self.log = kwargs.get("logger")
        self._APP_NAME = kwargs.get("app_name")
        self.app_home = make_splunkhome_path(["etc", "apps", self._APP_NAME])
        self.files_to_remove = kwargs.get("files_to_remove", [])
        self.elmo = False

    def remove_file(self, file_path):
        locations = [self.app_home] + file_path
        try:
            file_pathed = make_splunkhome_path(locations)
            self.log.info("action=checking_file file={}".format(file_pathed))
            if os.path.exists(file_pathed):
                os.remove(file_pathed)
                self.elmo = True
                self.log.info("action=file_deletion status=success file={}".format(file_pathed))
            else:
                self.log.debug("action=file_deletion status=not_found file={}".format(file_pathed))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.log.error("action=file_deletion status=failed file={} exception_line={} msg={}".format(file_path,
                                                                                                        exc_tb.tb_lineno,
                                                                                                        e))

    def snap(self):
        try:
            self.log.info("action=start app_home={}".format(self.app_home))
            self.log.info("action=remove_items status=start files={}".format(self.files_to_remove))
            [self.remove_file(x) for x in self.files_to_remove]
            self.log.info("action=ticklemeelmo elmo={}".format(self.elmo))
            if self.elmo:
                response, content = rest.simpleRequest("apps/local/{}/_reload".format(self._APP_NAME),
                                                       sessionKey=self.session_key,
                                                       getargs={'output_mode': 'json'})
                self.log.info("action=tickle_me_elmo response={}".format(response))
            self.log.info("action=remove_items status=end")
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.log.error("action=script_exection status=failed exception_line={} msg={}".format(exc_tb.tb_lineno, e))

class Utilities:
    """ Base Class for Utilities to help speed development """

    @property
    def _session_key(self):
        return self.__session_key

    @_session_key.setter
    def _session_key(self, x):
        self.__session_key = x

    @property
    def _app_name(self):
        return self.__app_name

    @_app_name.setter
    def _app_name(self, x):
        self.__app_name = x

    _log = None

    class HTTPError(Exception):
        def __init__(self, *args, **kwargs):
            response = kwargs.pop('response', None)
            self.response = response
            self.request = kwargs.pop('request', None)
            if response is not None and not self.request and hasattr(response, 'request'):
                self.request = self.response.request
            super(Exception, self).__init__(*args, **kwargs)

    def setup_logger(self, level=logging.INFO):
        """
        Setup a logger for the Utilities handler.
        """
        kl = KennyLoggins()
        self._log = kl.get_logger(self._app_name, "utilities", level)

    def __init__(self, log_level=logging.INFO, **kwargs):
        """Construct an instance of the Utilities Object"""
        self._session_key = kwargs["session_key"]
        self._app_name = kwargs["app_name"]
        self.setup_logger(log_level)
        self._isdebug = False

    def _debug(self, s):
        self._log.debug(s)

    def _build_endpoint_uri(self, entities):
        return entity.buildEndpoint(entities, namespace=self._app_name, owner="nobody")

    def _make_get_request(self, uri, args=None):
        return rest.simpleRequest(uri, getargs=args, sessionKey=self._session_key, raiseAllErrors=True)

    def _make_post_request(self, uri, args=None, usejson=False):
        if not usejson:
            return rest.simpleRequest(uri, postargs=args, sessionKey=self._session_key,
                                      raiseAllErrors=True)
        else:
            return rest.simpleRequest(uri, jsonargs=json.dumps(args), sessionKey=self._session_key)

    def _make_delete_request(self, uri, usejson=True):
        return rest.simpleRequest(uri, sessionKey=self._session_key, method="DELETE")

    def check_collection_exists(self, collection_name, do_create=False, **kwargs):
        t_name = re.sub('[^0-9a-zA-Z]+', '_', collection_name)
        c_name = "{}_col".format(t_name)
        uri = self._build_endpoint_uri(["storage", "collections", "config", c_name])
        try:
            sr, sc = self._make_get_request(uri, args={"output_mode": "json"})
            entry = json.loads(sc.decode("utf-8"))
            self._log.info("action=check_collection_exists do_create={} sc={}".format(do_create, type(entry)))
            self.check_transform_exists(t_name, do_create=do_create, collection=c_name, external_type="kvstore")
            if "fields_list" in kwargs:
                fl = kwargs["fields_list"]
                fl.append("_key")
                fl_s = ", ".join(sorted(list(set(fl))))
                self._log.info("action=update_fields_list fl={}".format(fl_s))
                self.update_transforms_property(t_name, "fields_list", fl_s)
                self.update_transforms_property(t_name, "collection", c_name)
            return entry
        except Exception as e:
            self._log.warn("action=check_collection_exists name={} do_create={} {}".format(c_name, do_create, e))
            ret_obj = {}
            if do_create:
                args = {"name": c_name, "output_mode": "json"}
                self._log.info("action=create_collection args={}".format(args))
                sr, sc = self._make_post_request(self._build_endpoint_uri(["storage", "collections", "config"]), args=args)
                entry = json.loads(sc.decode("utf-8"))
                self._log.info(
                    "action=check_collection_exists do_create={} response={}".format(do_create, json.dumps(entry)))
                self.check_transform_exists(t_name, do_create=do_create, collection=c_name, external_type="kvstore")
                ret_obj = entry
                if "fields_list" in kwargs:
                    fl = kwargs["fields_list"]
                    fl.append("_key")
                    fl_s = ", ".join(sorted(fl))
                    self._log.info("action=update_fields_list fl={}".format(fl_s))
                    self.update_transforms_property(t_name, "fields_list", fl_s)
                    self.update_transforms_property(t_name, "collection", c_name)
                return ret_obj
            else:
                return None
        return None

    def update_transforms_property(self, stanza, prop, value):
        uri = self._build_endpoint_uri(["configs", "conf-transforms", stanza])
        self._make_post_request(uri, args={prop: value})

    def check_transform_exists(self, transform_name, do_create=False, **kwargs):
        t_name = re.sub('[^0-9a-zA-Z]+', '_', transform_name)
        uri = self._build_endpoint_uri(["configs", "conf-transforms", t_name])
        try:
            sr, sc = self._make_get_request(uri, args={"output_mode": "json"})
            entry = json.loads(sc.decode("utf-8"))
            self._log.info("action=check_transform_exists do_create={} sc={}".format(do_create, json.dumps(entry)))
            return entry
        except Exception as e:
            self._log.warn("action=check_transform_exists name={} do_create={} {}".format(t_name, do_create, e))
            if do_create:
                kwargs["name"] = t_name
                kwargs["output_mode"] = "json"
                self._log.info("action=create_transform args={}".format(kwargs))
                sr, sc = self._make_post_request(self._build_endpoint_uri(["configs", "conf-transforms"]), args=kwargs)
                self._log.info("action=check_transform_exists do_create={} ".format(do_create))
                return json.loads(sc.decode("utf-8"))
            else:
                return None

    def get_proxy_configuration(self, proxy_name):
        """
        Get's the proxy configuration stanza specified from proxy.conf.
        :param proxy_name:
        :return:
        """
        try:
            uri = self._build_endpoint_uri(['configs', 'conf-proxy', proxy_name])
            server_response, server_content = self._make_get_request(uri, args={"output_mode": "json"})
            proxy_configuration = json.loads(server_content)["entry"][0]["content"]
            proxy_config = {"host": proxy_configuration.get("proxy_host"),
                            "port": proxy_configuration.get("proxy_port"),
                            "useSSL": "true" if proxy_configuration.get("use_ssl") in ["true", "1", 1] else "false"
                            }
            if proxy_configuration["proxy_credential"] is not "none":
                proxy_configuration["proxy_pass"] = "{}".format(self.get_credential(self._app_name,
                                                                                    proxy_configuration[
                                                                                        "proxy_credential"]))
                proxy_config["authentication"] = {
                    "username": proxy_configuration.get("proxy_user"),
                    "password": proxy_configuration.get("proxy_pass")
                }
            return json.loads(json.dumps(proxy_config))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            jsondump = {"message": str((e)),
                        "exception_type": "%s" % type(e),
                        "exception_arguments": "%s" % e,
                        "filename": fname,
                        "line": exc_tb.tb_lineno
                        }
            raise Exception(json.dumps(jsondump))

    def get_search_results_by_sid(self, sid, **kwargs):
        try:
            uri = self._build_endpoint_uri(['search', 'jobs', sid, 'results'])
            server_response, server_content = self._make_get_request(uri, args={"count": kwargs.get("count", 10000),
                                                                                "output_mode": "json"})
            return json.loads(server_content)["results"]
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            raise Exception(myJson)

    def send_single_event(self, event={}, **kwargs):
        try:
            uri = self._build_endpoint_uri(['receivers', 'simple'])
            server_response, server_content = self._make_post_request(
                "{}?index={}&sourcetype={}&source={}".format(uri, kwargs.get("index", "main"),
                                                             kwargs.get("sourcetype",
                                                                        "utilities_call"),
                                                             kwargs.get("source",
                                                                        "utilities_call")),
                args=json.dumps(kwargs.get("event", {})))
            return json.loads(server_content)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            raise Exception(myJson)

    def set_credential(self, crealm, cuser, cpass):
        self._debug("setting creds")
        uri = self._build_endpoint_uri(['storage', 'passwords'])
        args = {"name": cuser, "realm": crealm, "password": cpass}
        creds = self.get_credential(crealm, cuser)
        if creds is not None:
            self._debug("updating creds")
            uri = self._build_endpoint_uri(['storage', 'passwords', "{0}:{1}".format(crealm, cuser)])
            args = {"password": cpass}
        return self._make_post_request(uri, args)

    def get_configuration(self, filename, stanza):
        try:
            rc, o = self._make_get_request(self._build_endpoint_uri(["configs", "conf-{}".format(filename), stanza]),
                                          args={"output_mode": "json"})
            self._log.debug("action=get_configuration typeobj={} rc={} typerc={} compare={}".format(type(o), rc.status, type(rc.status), (rc.status == 200)))
            if rc.status == 200:
                self._log.debug("action=get_configuration o={}".format(o))
                obj = json.loads(o)
                content = obj["entry"][0]["content"]
                self._log.debug("action=get_configuration content={}".format(content))
                return {k: v for k, v in content.items() if not k.startswith('eai:') and k != "disabled"}
            else:
                return {}
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error('message="{}" exception_type="{}" '
                            'exception_arguments="{}" filename="{}" exception_line="{}" '.format(str(e), type(e), e, fname, exc_tb.tb_lineno))
            return {}

    def get_credential(self, realm, cuser):
        """
        :param realm:
        :param cuser:
        :return:
        """
        try:
            self._log.info("realm={} cuser={} app={}".format(realm, cuser, self._app_name))
            entities = entity.getEntities(['storage', 'passwords'], namespace=self._app_name, owner='nobody',
                                          sessionKey=self._session_key, search="{0}:{1}".format(realm, cuser))
            key = "{0}:{1}:".format(realm, cuser)
            if key not in entities:
                return None
            else:
                import urllib
                try:
                    clear_pass = entities[key]["clear_password"]
                    if clear_pass is None:
                        self._log.error(
                            "action=get_credential msg=could_not_decrypt_clear_password realm={} cuser={} ".format(
                                realm, cuser))
                        return None
                    self._log.debug(
                        "action=get_credential msg=found_clear_password realm={} cuser={} ".format(realm,
                                                                                                   cuser))
                    return clear_pass
                except KeyError as e:
                    return None
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            jsondump = {"message": str((e)),
                        "exception_type": "%s" % type(e),
                        "exception_arguments": "%s" % e,
                        "filename": fname,
                        "line": exc_tb.tb_lineno
                        }
            self._log.error('message="{}" exception_type="{}" '
                            'exception_arguments="{}" filename="{}" line="{}" '.format(str(e), type(e), e, fname, exc_tb.tb_lineno))
            raise Exception(json.dumps(jsondump))

    def get_kvstore_data(self, kvstore, search=None):
        try:
            uri = self._build_endpoint_uri(['storage', 'collections', 'data', kvstore])
            server_response, server_content = self._make_get_request(uri, args={"query": search})
            return json.loads(server_content)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            raise Exception(myJson)

    def is_kvstore_ready(self):
        return self.get_kvstore_status() == "ready"

    def get_kvstore_status(self):
        uri = self._build_endpoint_uri(["kvstore", "status"])
        headers, data = self._make_get_request(self._build_endpoint_uri(["kvstore", "status"]),
                                               args={"output_mode": "json"})
        return json.loads(data)["entry"][0]["content"]["current"]["status"]

    def kvstore_batch_save(self, kvstore, data):
        try:
            uri = self._build_endpoint_uri(["storage", "collections", "data", kvstore, "batch_save"])
            # self._make_post_request(uri, args=data, usejson=True)
            chunks = [data[i:i + 500] for i in range(0, len(data), 500)]
            returns = []
            for chunk in chunks:
                # We split this into chunks of 500, which is 1/2 the default limit.conf setting for document size
                self._debug("ksvtore={} action=batch_save chunk_length={}".format(kvstore, len(chunk)))
                returns.extend(self._make_post_request(uri, args=chunk, usejson=True))
            return returns
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            raise Exception(myJson)

    def set_kvstore_data(self, kvstore, data):
        try:
            uri = self._build_endpoint_uri(["storage", "collections", "data", kvstore])
            self._log.info("setting kvstore data to have fields: {}".format(json.dumps({"keys": data.keys()})))
            return self._make_post_request(uri, args=data, usejson=True)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            raise Exception(myJson)

    def delete_kvstore_all_items(self, kvstore):
        try:
            uri = self._build_endpoint_uri(["storage", "collections", "data", kvstore])
            self._log.info("action=deleting_kvstore_item kvstore={}".format(kvstore))
            return self._make_delete_request(uri, usejson=True)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.error(myJson)
            return {"status": "failed", "action": "delete_kvstore_item", "kvstore": kvstore}

    def delete_kvstore_item(self, kvstore, key):
        try:
            uri = self._build_endpoint_uri(["storage", "collections", "data", kvstore, key])
            self._log.info("action=deleting_kvstore_item kvstore={} key={}".format(kvstore, key))
            return self._make_delete_request(uri, usejson=True)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            myJson = "message=\"{}\" exception_type=\"{}\" exception_arguments=\"{}\" filename=\"{}\" line=\"{}\" ".format(
                str(e), type(e), e, fname, exc_tb.tb_lineno)
            self._log.warn(myJson)
            return {"status": "failed", "action": "delete_kvstore_item", "key": key, "kvstore": kvstore}

    def update_kvstore_data(self, kvstore, key, data):
        uri = self._build_endpoint_uri(["storage", "collections", "data", kvstore, key])
        self._debug("URI: %s " % uri)
        self._debug("DATA: %s" % data)
        return self._make_post_request(uri, args=data, usejson=True)

    def get_kvstore_proxy_configuration(self, realm, kvstore):
        """
        :param realm:
        :param kvstore:
        :return:
        """
        kvstore_configurations = self.get_kvstore_data(kvstore, search=json.dumps({"_key": realm}))
        kv = kvstore_configurations[0]
        self._debug("KVSTORE: %s" % kvstore_configurations)
        proxy_sensitive = {"username": None, "password": None}
        if "proxy_user" in kv:
            ps = self.get_credential(realm, kv["proxy_user"])
            self._debug("PS: %s" % ps)
            proxy_sensitive = {"username": kv["proxy_user"],
                               "password": ps["clear_password"]}
        proxy_settings = {"host": kv["proxy_host"],
                          "port": kv["proxy_port"],
                          "authentication": proxy_sensitive,
                          "key": realm,
                          "protocol": kv["proxy_protocol"]
                          }
        return proxy_settings

    def set_kvstore_proxy_configuration(self, kvstore, proxy_host, proxy_port, proxy_user=None, proxy_pass=None,
                                        proxy_protocol="http"):
        """
        :param kvstore:
        :param proxy_host:
        :param proxy_port:
        :param proxy_user:
        :param proxy_pass:
        :param proxy_protocol: Default is "HTTP". Valid options are
        :return:
        """
        args = {"proxy_host": proxy_host, "proxy_port": proxy_port, "proxy_protocol": proxy_protocol}
        self._debug("DATA: %s" % json.dumps(args))
        if proxy_user is not None:
            args["proxy_user"] = proxy_user
        resp, content = self.set_kvstore_data(kvstore, args)
        cnt = json.loads(content)
        self._debug("%s" % json.dumps(cnt))
        key = cnt["_key"]
        update_args = {"realm": key, "proxy_host": proxy_host, "proxy_port": proxy_port,
                       "proxy_protocol": proxy_protocol}
        if proxy_user is not None:
            self.set_credential(key, proxy_user, proxy_pass)
            update_args["proxy_user"] = proxy_user
        self.update_kvstore_data(kvstore, key, update_args)
        return key

    def del_kvstore_proxy_configuration(self, key):
        return True

    def is_cloud(self):
        try:
            uri = self._build_endpoint_uri(["server", "info", "server_info"])
            sr, sc = self._make_get_request(uri, args={"output_mode": "json"})
            instance_type = sc[0]['content']['instance_type']
            self._log.info("checking_cloud={}".format(json.loads(sc.decode("utf-8"))))
            return instance_type == "cloud"
        except:
            return False

    def read_lookup(self, lookup_filename, primary_key=None):
        try:
            lookups_dir = os.path.join(get_apps_dir(), self._app_name, "lookups")
            lookup_file = os.path.join(lookups_dir, lookup_filename)
            lookup_dict = {"lookup": [], "primary_keys": []}
            if not os.path.isfile(lookup_file):
                return lookup_dict
            with open(lookup_file, mode='r') as infile:
                reader = csv.DictReader(infile)
                for row in reader:
                    if primary_key is not None and primary_key in row:
                        lookup_dict["primary_keys"].append(row[primary_key])
                    lookup_dict["lookup"].append(row)
            return lookup_dict
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            jsondump = {"message": str((e)),
                        "exception_type": "%s" % type(e),
                        "exception_arguments": "%s" % e,
                        "filename": fname,
                        "line": exc_tb.tb_lineno
                        }
            raise Exception(json.dumps(jsondump))

    def write_lookup(self, lookup_filename, data):
        try:
            lookups_dir = os.path.join(get_apps_dir(), self._app_name, "lookups")
            if not os.path.isdir(lookups_dir):
                os.mkdir(lookups_dir, mode=0o744)
            lookup_file = os.path.join(lookups_dir, lookup_filename)
            mode = 'w'
            if not os.path.isfile(lookup_file):
                mode = 'w+'
            header = []
            for row in data:
                for item in row:
                    if row[item] is None:
                        row[item] = ""
                    if item not in header:
                        header.append(item)
                    if len("{}".format(row[item])) > 0:
                        row[item] = "{}".format(row[item]).strip()
            self._debug("{}".format(json.dumps(header)))
            with open(lookup_file, mode) as outfile:
                writer = csv.DictWriter(outfile, fieldnames=header)
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
            return data
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            jsondump = {"message": str((e)),
                        "exception_type": "%s" % type(e),
                        "exception_arguments": "%s" % e,
                        "filename": fname,
                        "line": exc_tb.tb_lineno
                        }
            raise Exception(json.dumps(jsondump))

    def update_lookup(self, lookup_filename, data, primary_key=None):
        existing_data = self.read_lookup(lookup_filename, primary_key=primary_key)
        for row in data:
            if primary_key is None:
                existing_data["lookup"].append(row)
            else:
                if row[primary_key] not in existing_data["primary_keys"]:
                    existing_data["lookup"].append(row)
        return self.write_lookup(lookup_filename, existing_data["lookup"])

