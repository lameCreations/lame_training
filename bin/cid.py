import sys
import logging
from Utilities import KennyLoggins
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

_APP_NAME = "CorelightForSplunk"
_cmd_name = "cid"
sys.path.insert(0, make_splunkhome_path(["etc", "apps", _APP_NAME, "lib"]))
from splunklib.searchcommands import Configuration, EventingCommand, Option, validators, dispatch
import communityid
kl = KennyLoggins()


@Configuration()
class CidCommand(EventingCommand):
    funcs = {
        "tcp": communityid.FlowTuple.make_tcp,
        "udp": communityid.FlowTuple.make_udp,
        "icmp": communityid.FlowTuple.make_icmp,
        "icmp6": communityid.FlowTuple.make_icmp6,
        "sctp": communityid.FlowTuple.make_sctp
    }

    output_field = Option(
        doc='''
            **Syntax:** **output_field=***<fieldname>*
            **Description:** The field to output into. Default: "cid" ''',
        require=False, validate=validators.Fieldname(), default="cid")

    def transform(self, events):
        # transport src_ip_var, dest_ip_var, src_port_var, dest_port_var
        log = kl.get_logger(app_name=_APP_NAME, file_name=_cmd_name, log_level=logging.INFO)
        log.debug("action=starting_cmd_transform cmd={} config={} output_field={} fieldnames={}".format(
            _cmd_name, self.service, self.output_field, self.fieldnames))
        cid = communityid.CommunityID()
        if len(self.fieldnames) != 5:
            raise ValueError("Must include these fields/values: transport src_ip dest_ip src_port dest_port")
        for evt in events:
            if not self.output_field in evt:
                evt[self.output_field] = "-"
            args = [evt[x] if x in evt else x for x in self.fieldnames]
            transport = args.pop(0)
            log.debug("action=check_values evt={} args={} transport={}".format(evt, args, transport))
            if transport in self.funcs.keys():
                tpl = self.funcs[transport](*args)
                evt[self.output_field] = cid.calc(tpl)
                log.debug("action=check_output tpl={} cid={}".format(tpl, evt[self.output_field]))
            yield evt

dispatch(CidCommand, sys.argv, sys.stdin, sys.stdout, __name__)