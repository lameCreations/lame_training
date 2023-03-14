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
import os.path
import os
import sys
import splunk.rest as rest
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import aplspl.version as version

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