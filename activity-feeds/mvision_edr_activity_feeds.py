#!/usr/bin/env python3
# Written by mohlcyber v.0.4 (15.04.2020)

import sys
import getpass
import json
import logging

from argparse import ArgumentParser, RawTextHelpFormatter
from dxlstreamingclient.channel import Channel, ChannelAuth

# Topics to subscribe: 'case-mgmt-events', 'BusinessEvents', 'threatEvents'
TOPICS = ['threatEvents']


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.url = 'https://api.soc.eu-central-1.mcafee.com/'
        elif args.region == 'US':
            self.url = 'https://api.soc.mcafee.com/'
        self.user = args.user
        self.pw = args.password
        self.auth = ChannelAuth(self.url, self.user, self.pw, verify_cert_bundle='')

        loglevel = args.loglevel

        logging.basicConfig(level=getattr(logging, loglevel.upper(), None))
        logger = logging.getLogger()
        ch = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    def activity_feed(self):
        logging.info("Starting event loop...")
        try:
            with Channel(self.url, auth=self.auth, consumer_group='mvisionedr_events', verify_cert_bundle='') as channel:
                def process_callback(payloads):
                    if not payloads == []:
                        for payload in payloads:
                            print('Event received: {0}'.format(json.dumps(payload)))
                            if args.module:
                                self.run_modules(payload)
                    return True

                channel.run(process_callback, wait_between_queries=5, topics=TOPICS)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def run_modules(self, payload):
        try:
            import modules.modules
            dict_kwargs = {}
            for arg in args.command:
                arg_tmp = arg.split('=')
                dict_kwargs[arg_tmp[0]] = arg_tmp[1]

            mclass = getattr(modules.modules, args.module)
            mclass(dict_kwargs).run(payload)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


if __name__ == "__main__":

    usage = """python mvision_edr_activity_feeds.py -R <REGION> -U <USERNAME> -L <LOGLEVEL>"""
    title = 'McAfee EDR Activity Feeds'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US'])

    parser.add_argument('--user', '-U',
                        required=True, type=str,
                        help='MVISION EDR Username')

    parser.add_argument('--password', '-P',
                        required=False, type=str,
                        help='MVISION EDR Password')

    parser.add_argument('--module', '-M',
                        required=False, type=str,
                        help='Modules', choices=['Syslog', 'TheHive', 'Email', 'ServiceNow'])

    parser.add_argument('--command', '-C',
                        required=False, type=str,
                        help='Commands for Modules: \n'
                        ' \n'+
                        'For Syslog please use the following commands: \n' +
                        '-C syslog=<Syslog Server IP> -C port=<PORT>\n' +
                        ' \n' +
                        'For TheHive please use the following commands: \n' +
                        '-C url=<URL to TheHive http://> -C port=<PORT> -C token=<TOKEN> \n' +
                        ' \n' +
                        'For Email please use the following commands: \n' +
                        '-C smtp=<IP to SMTP server> -C port=<PORT> -C user=<SMTP User> -C pw=<SMTP PW> -C recipient=<Recipient>\n' +
                        ' \n' +
                        'For ServiceNow please use the following commands: \n' +
                        '-C url=<URL to SNOW Instance> -C user=<SNOW User> -C pw=<SNOW PW>\n' +
                        ' \n'
                        , action='append')

    parser.add_argument('--loglevel', '-L',
                        required=False, type=str,
                        default='info', choices=['critical', 'error', 'warning',
                                 'info', 'debug', 'notset'])

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass(prompt='MVISION EDR Password:')

    edr = EDR()
    edr.activity_feed()
