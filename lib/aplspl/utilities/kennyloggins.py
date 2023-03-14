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

import logging
import os
import sys
from logging import handlers
import splunk
import splunk.entity as entity
import splunk.rest as rest
from splunk.appserver.mrsparkle.lib.util import get_apps_dir
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import aplspl.version as version


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


