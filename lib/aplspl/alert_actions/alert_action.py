from __future__ import absolute_import
from json import dumps, loads

import sys
import os
import csv
import gzip
import splunk.auth as auth
import requests
import time
import logging
import uuid
import re

from aplspl.alert_actions.cim_actions import ModularAction
from aplspl.utilities.kennyloggins import KennyLoggins
from aplspl.utilities.utilities import Utilities
from itertools import chain
from collections import defaultdict
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path


class CreateAlertModularAction(ModularAction):
    def __init__(self, settings, action_name='unknown', app_name="",
                 global_configuration={}):
        ModularAction.__init__(self, settings, logger=logging, action_name=action_name)
        try:
            kl = KennyLoggins()
            self._log = kl.get_logger(app_name=app_name, file_name="{}".format(action_name),
                                      log_level=logging.INFO)
            self._log.debug("action=init setup_logger=true")
            self.app_name = app_name
            self.aa_name = action_name
            self._splunk_url = auth.splunk.getLocalServerInfo()
            try:
                self.payload = loads(settings)
            except ValueError:
                self._log.info('No alerts to process!')
                sys.exit(2)
            self._log.debug("action=loading_session_key")
            self.sessionKey = self.payload.get('session_key', None)
            self._log.debug("action=instantiate_utilities session_key_length={}".format(len(self.sessionKey)))
            self.utils = Utilities(app_name=app_name, session_key=self.sessionKey)
            self._log.debug("action=get_configuration global_configuration={}".format(dumps(global_configuration)))
            self.configuration = self.utils.get_configuration(global_configuration.get("filename", ""),
                                                              global_configuration.get("stanza", ""))
            self._log.debug("action=get_configuration config={}".format(self.configuration))
            for k, v in self.configuration.iteritems():
                self._log.debug("action=setting_attr {}={}".format(k, v))
                setattr(self, k, v)
            self._log.debug("action=get_settings settings={}".format(self.configuration))
            self._verify_requests = self.configuration.get("verify_requests", False)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error(
                "action=fatal_error exception_line={} file={}  message={}".format(exc_tb.tb_lineno, fname, e))

    def _build_url(self, endpoint, search=None):
        return "{}/servicesNS/nobody/{}/{}/?output_mode=json".format(
            self._splunk_url, self.app_name, "/".join(endpoint)
        )

    def _load_results(self):
        return gzip.open(self.payload.get("results_file"), 'rb')

    def _load_lookups(self, fltr):
        all_fields = {}
        all_fields_list = defaultdict(list)
        url = self._build_url(["data", "lookup-table-files"], search=fltr)
        r = self._get(url)

        sc = r.status_code
        if sc != 200:
            raise Exception("Unable to query rest url {}".format(url))
        self._log.debug("action=load_lookup_rest r={}".format(dumps(r.json()["entry"])))
        seen_ids = set()
        for lup in r.json()["entry"]:
            lookup = self._load_lookup(lup["name"])
            for k, v in chain(all_fields.items(), lookup.items()):
                if v["id"] not in seen_ids:
                    all_fields_list[k].append(v)
                    seen_ids.add(v["id"])
            all_fields.update(lookup)
        return all_fields_list

    def _load_kvstore(self, kvstore_name):
        try:
            return self.utils.get_kvstore_data(kvstore_name)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_load_kvstore exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                                  fname, e))

    def _delete_kvstore_items(self, kvstore_name, data):
        try:
            # delete_kvstore_item
            res = [self.utils.delete_kvstore_item(kvstore_name, x.get("_key")) for x in data if
                   x.get("_key") is not None]
            self._log.debug("action=delete_kvstore_items result={}".format(res))
            return res
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_load_kvstore exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                                  fname, e))

    def _save_kvstore(self, kvstore_name, field_name, data):
        try:
            res = self.utils.kvstore_batch_save(kvstore_name,
                                                [{"_key": zz.get("_key", "{}".format(uuid.uuid4())),
                                                  field_name: zz.get("value", "")} for zz in
                                                 data])
            self._log.debug("action=save_batch_kvstore result={}".format(res))
            return res
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_load_kvstore exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                                  fname, e))

    def _load_lookup(self, lookup_name):
        try:
            url = self._build_url(["data", "lookup-table-files", lookup_name])
            r = self._get(url)
            sc = r.status_code
            if sc != 200:
                raise Exception("{} Lookup not found. ".format(lookup_name))
            rj = r.json()["entry"][0]
            path = rj["content"]["eai:data"]
            self._log.debug("reading lookup path from {}".format(path))
            keys = []
            with open(path) as fh:
                lookup = csv.DictReader(fh)
                for line in lookup:
                    keys.append(line)
            self._log.debug("action=load_csv sc={} url={} path={}".format(sc, url, path))
            return keys
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_load_lookup exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                                 fname, e))

    def get_column_values(self, lookup_data, column):
        return [x.get(column) for x in lookup_data if x.get(column) is not None]

    def _save_lookup(self, lookup_name, data):
        url = self._build_url(["data", "lookup-table-files", lookup_name])
        tmpfile = make_splunkhome_path(["etc", "apps", self.app_name, "lookups", "tmp_{}".format(lookup_name)])
        self._log.debug("creating tmpfile={}".format(tmpfile))
        with open(tmpfile, "w+") as fh:
            w = csv.DictWriter(fh, [x for x in data[0]])
            w.writeheader()
            w.writerows(data)
        r = self._post(url, {"eai:data": tmpfile})
        self._log.info("action=save_lookup name={} status_code={}".format(lookup_name, r.status_code))
        try:
            os.remove(tmpfile)
        except Exception as e:
            pass

    def current_milli_time(self):
        return float(time.time())

    def _create_lookup(self, lookup_name, data):
        url = self._build_url(["data", "lookup-table-files"])
        # Source file Staging area is /opt/splunk/var/run/splunk/lookup_tmp/
        # THIS IS ENFORCED BY SPLUNK AND IT CANNOT BE CHANGED
        staging = make_splunkhome_path(["var", "run", "splunk", "lookup_tmp"])
        if not os.path.exists(staging):
            os.makedirs(staging)
        tmpfile = os.path.join(staging, "tmp_{}".format(lookup_name))
        self._log.debug("creating tmpfile={}".format(tmpfile))
        with open(tmpfile, "w+") as fh:
            w = csv.DictWriter(fh, [x for x in data[0]])
            w.writeheader()
            w.writerows(data)
        r = self._post(url, {"name": lookup_name, "eai:data": tmpfile})
        self._log.info("action=create_lookup name={} status_code={} ret={} url={}".format(lookup_name, r.status_code,
                                                                                          dumps(r.json()), url))
        os.remove(tmpfile)
        return data

    def __f(self, x):
        fi = x.get("field_splunk", None)
        unk = "unknown_{}".format(x["field_name"])
        if fi is None:
            return unk
        elif len(fi) < 1:
            return unk
        elif fi == "unk" or fi == "unknown":
            return unk
        else:
            return fi

    def _post(self, url, data):
        try:
            return requests.post(url=url, data=data, headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                                 verify=self._verify_requests)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_post exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                          fname, e))

    def _delete(self, url):
        try:
            return requests.delete(url=url, headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                                   verify=self._verify_requests)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_delete line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                  fname, e))

    def _get(self, url):
        try:
            return requests.get(url=url,
                                headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                                verify=self._verify_requests)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=_get exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                         fname, e))

    def getSessionKey(self):
        return self.sessionKey

    def get_evtidx(self, evt):
        try:
            self._log.info("function=_get_evtidx")
            r = self._get(self._build_url(["saved", "eventtypes", evt]))
            self._log.info("evtidx_rc=".format(r.status_code))
            base_evttype = r.json()["entry"][0]["content"]["search"]
            evt = re.compile(r'index\s*=\s*([a-z\d_\-]+)')
            found = evt.match(base_evttype)
            self._log.info("found=evt_re re={} match={}".format(evt, found.groups()[0]))
            return r.status_code, found.groups()[0]
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self._log.error("function=get_evtidx exception_line={} file={}  message={}".format(exc_tb.tb_lineno,
                                                                                               fname, e))

    def _get_spl(self, sid):
        self._log.debug("function=_get_spl sid={}".format(sid))
        url = self._build_url(["search", "jobs", sid], search=None)
        self._log.debug("pulling sid from url {}".format(url))
        r = self._get(url)
        sc = r.status_code
        if sc == 200:
            self._log.debug("response {}".format(dumps(r.json()["entry"][0]["content"]["request"])))
            cont = r.json()["entry"][0]["content"]
            if "search" in cont["request"]:
                return cont["request"]["search"]
            else:
                return "{} | {}".format(cont["eventSearch"], cont["reportSearch"])
        return ""

    def _check_true(self, v):

        if v == "TRUE" or v == 1 or v == "True" or v is True or v == "1":
            self._log.debug("action=_check_true v={} result=True".format(v))
            return True
        else:
            self._log.debug("action=_check_true v={} result=False".format(v))
            return False

    def main(self):
        raise Exception("Not Implemented")
