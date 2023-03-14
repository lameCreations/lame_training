import json
import logging
import os
import sys

import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from splunk_app_stream.models.stream import *

import Utilities


def setup_logger(level):
    """
    Setup a logger for the REST handler.
    """

    logger = logging.getLogger('splunk.appserver.controllers.apl_utilities')
    logger.propagate = False  # Prevent the log messages from being duplicated in the python.log file
    logger.setLevel(level)
    file_handler = logging.handlers.RotatingFileHandler(
        make_splunkhome_path(['var', 'log', 'splunk', 'apl_utilities.log']), maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


logger = setup_logger(logging.INFO)


class Utilities(controllers.BaseController):
    def _catch_error(self, e):
        myJson = {"log_level": "ERROR"}
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        myJson["errors"] = [{"msg": str(e),
                             "exception_type": "%s" % type(e).__name__,
                             "exception_arguments": "%s" % e,
                             "filename": fname,
                             "line": exc_tb.tb_lineno
                             }]
        return myJson

    # /custom/_app_name/utilities/proxy_configuration
    @route('/:id')
    @expose_page(must_login=True, methods=['GET', "POST"])

    def proxy_configuration(self, id='', **kwargsraw):
        try:
            sessionKey = cherrypy.session.get('sessionKey')
            app_name = cherrypy.request.path_info.split('/')[3]
            aplutil = Utilities.Utilities(sessionKey=sessionKey, app_name=app_name)
            method = cherrypy.request.method
            if method == "GET":
                return self.parse_json_payload(aplutil.get_proxy_configuration(id, "proxy_configuration"))

        except Exception as e:
            logger.error("%s" % self._catch_error(e))

    def parse_json_payload(self):
        """Read request payload and parse it as JSON"""
        body = cherrypy.request.body.read()
        if not body:
            raise Exception('request payload empty')

        try:
            data = json.loads(body)
        except Exception as e:
            logger.exception(e)
            raise Exception('could not parse JSON payload')
        return data
