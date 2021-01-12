#!/usr/bin/env python3
# Written by mohlcyber v.0.6 (12.01.2021)

import sys
import getpass
import json
import logging
import requests

from argparse import ArgumentParser, RawTextHelpFormatter
from dxlstreamingclient.channel import Channel, ChannelAuth

requests.packages.urllib3.disable_warnings()

# Topics to subscribe: 'case-mgmt-events', 'BusinessEvents', 'threatEvents'
TOPICS = ['threatEvents']


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.url = 'https://api.soc.eu-central-1.mcafee.com/'
        elif args.region == 'US':
            self.url = 'https://api.soc.mcafee.com/'
        elif args.region == 'SY':
            self.url = 'https://api.ap-southeast-2.soc.mcafee.com/'
        self.user = args.user
        self.pw = args.password
        self.auth = ChannelAuth(self.url, self.user, self.pw, verify_cert_bundle='')

        self.enrich = args.enrich
        loglevel = args.loglevel

        self.buffer = {}

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

                            if self.enrich == 'True':
                                payload = self.epo_enrich(payload)

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

    def epo_enrich(self, payload):
        try:
            if 'threat' in payload:
                maGuid = payload['threat']['maGuid']
                if maGuid not in self.buffer:
                    data = EPO().request('system.find', data={'searchText': maGuid})
                    if data is not None:
                        print('INFO: Going to enrich maGuid {}.'.format(maGuid))
                        for hostinfo in data:
                            tmp_buffer = []
                            payload['threat']['maHostname'] = hostinfo['EPOComputerProperties.IPHostName']
                            tmp_buffer.append(hostinfo['EPOComputerProperties.IPHostName'])
                            payload['threat']['maName'] = hostinfo['EPOComputerProperties.ComputerName']
                            tmp_buffer.append(hostinfo['EPOComputerProperties.ComputerName'])
                            payload['threat']['maIP'] = hostinfo['EPOComputerProperties.IPAddress']
                            tmp_buffer.append(hostinfo['EPOComputerProperties.IPAddress'])
                            payload['threat']['maTags'] = hostinfo['EPOLeafNode.Tags']
                            tmp_buffer.append(hostinfo['EPOLeafNode.Tags'])
                            self.buffer[maGuid] = tmp_buffer
                    else:
                        print('INFO: Could not enrich maGuid {0}. EPO Bad Response'.format(maGuid))
                else:
                    print('INFO: Data for enrichment already in buffer for maGuid {0}.'.format(maGuid))
                    payload['threat']['maHostname'] = self.buffer[maGuid][0]
                    payload['threat']['maName'] = self.buffer[maGuid][1]
                    payload['threat']['maIP'] = self.buffer[maGuid][2]
                    payload['threat']['maTags'] = self.buffer[maGuid][3]

            return payload

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


class EPO():

    def __init__(self):
        self.epo_ip = args.epo_ip
        self.epo_port = str(args.epo_port)
        self.epo_user = args.epo_user
        self.epo_pwd = args.epo_pwd

        self.session = requests.Session()

    def request(self, option, **kwargs):
        try:
            hostinfo = None
            kwargs.setdefault('auth', (self.epo_user, self.epo_pwd))
            kwargs.setdefault('verify', False)
            kwargs.setdefault('params', {})
            kwargs['params'][':output'] = 'json'

            url = 'https://{0}:{1}/remote/{2}'.format(self.epo_ip, self.epo_port, option)

            res = self.session.post(url, **kwargs)
            if res.ok and res.text.startswith('OK:'):
                hostinfo = json.loads(res.text[3:])

            return hostinfo

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


if __name__ == "__main__":

    usage = """python mvision_edr_activity_feeds.py -h"""
    title = 'McAfee EDR Activity Feeds'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US', 'SY'])

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

    parser.add_argument('--enrich', required=False,
                        type=str, help='Enrich MAGUID with EPO',
                        default='False', choices=['True', 'False'])

    parser.add_argument('--epo-ip', type=str,
                        required=False, help='ePO Server IP or hostname')

    parser.add_argument('--epo-port', type=int,
                        default=8443, required=False,
                        help='ePO Server Port')

    parser.add_argument('--epo-user', type=str,
                        required=False, help='ePO Server User')

    parser.add_argument('--epo-pwd', type=str,
                        required=False, help='ePO Server Password')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass(prompt='MVISION EDR Password:')
    if not args.epo_pwd:
        args.epo_pwd = getpass.getpass(prompt='McAfee ePO Password:')

    edr = EDR()
    edr.activity_feed()
