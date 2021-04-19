#!/usr/bin/env python3
# Written by mohlcyber v.0.5 (19.04.2021)
# Script to retrieve all threats from the monitoring dashboard

import sys
import getpass
import requests
import time
import logging
import json

from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta
from logging.handlers import SysLogHandler


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.base_url = 'soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'soc.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'soc.ap-southeast-2.mcafee.com'

        self.verify = True
        self.logging()

        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.minutes = args.minutes
        self.limit = args.limit

        self.details = args.details
        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'

    def logging(self):
        # setup the console logger
        self.logger = logging.getLogger('logs')
        self.logger.setLevel('DEBUG')
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # setup the syslog logger
        if args.syslog_ip is not None:
            if args.syslog_port is not None:
                self.syslog = logging.getLogger('syslog')
                self.syslog.setLevel('DEBUG')
                self.syslog.addHandler(SysLogHandler(address=(args.syslog_ip, args.syslog_port)))
            else:
                self.logger.error('Please provide also the Syslog Port')
                sys.exit()

    def auth(self, creds):
        try:
            res = self.request.get('https://api.' + self.base_url + '/identity/v1/login', auth=creds)

            if res.ok:
                token = res.json()['AuthorizationToken']
                self.request.headers = {'Authorization': 'Bearer {}'.format(token)}
                self.logger.debug('AUTHENTICATION: Successfully authenticated')
            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()
        except Exception as error:
            self.logger.error('Error in edr.auth(). Error: {}'.format(str(error)))

    def get_threats(self):
        try:
            t_before = (datetime.utcnow() - timedelta(minutes=self.minutes)).strftime(self.pattern)
            epoch_before = int(time.mktime(time.strptime(t_before, self.pattern)))

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities

            res = self.request.get(
                'https://api.' + self.base_url + '/ft/api/v2/ft/threats?sort=-rank&filter={0}&from={1}&limit={2}'
                .format(json.dumps(filter), str(epoch_before * 1000), str(self.limit)))

            if res.ok:
                self.logger.info('SUCCESS: Successful retrieved threats.')

                res = res.json()

                for threat in res['threats']:
                    # Enrich with detections
                    detections = self.get_detections(threat['id'])
                    threat['url'] = 'https://ui.' + self.base_url + '/monitoring/#/workspace/72,TOTAL_THREATS,{0}' \
                        .format(threat['id'])
                    threat['detections'] = detections

                    # Enrich with trace
                    if self.details == 'True':
                        for detection in threat['detections']['detections']:
                            maGuid = detection['host']['maGuid']
                            traceId = detection['traceId']

                            traces = self.get_trace(maGuid, traceId)
                            detection['traces'] = traces

                self.logger.info(json.dumps(res))
                if args.syslog_ip and args.syslog_port:
                    for threat in res['threats']:
                        self.syslog.info(json.dumps(threat, sort_keys=True))
            else:
                self.logger.error('Error in edr.get_threats(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            self.logger.error('Error in edr.get_threats(). Error: {}'.format(str(error)))

    def get_detections(self, threatId):
        try:
            res = self.request.get('https://api.' + self.base_url + '/ft/api/v2/ft/threats/{0}/detections'
                                   .format(threatId))

            if res.ok:
                return res.json()
            else:
                self.logger.error('Error in retrieving edr.get_detections(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            self.logger.error('Error in edr.get_detections(). Error: {}'.format(str(error)))

    def get_trace(self, maGuid, traceId):
        try:
            res = self.request.get('https://api.' + self.base_url +
                                   '/historical/api/v1/traces/main-activity-by-trace-id?maGuid={0}&traceId={1}'
                                   .format(maGuid, traceId))

            if res.ok:
                return (res.json())
            else:
                self.logger.error('Error in edr.get_trace(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            self.logger.error('Error in edr.get_trace(). Error: {}'.format(str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -M <MINUTES> -L <MAX RESULTS> -S <SYSLOG IP> -SP <SYSLOG PORT>"""
    title = 'McAfee EDR Python API'
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

    parser.add_argument('--details', '-D',
                        required=False, type=str, choices=['True', 'False'],
                        default='False',
                        help='Enrich threat information with trace data')

    parser.add_argument('--minutes', '-M',
                        required=True, type=int,
                        help='Timeframe to pull data in minutes')

    parser.add_argument('--limit', '-L',
                        required=True, type=int,
                        help='Maximum number of returned items')

    parser.add_argument('--syslog-ip', '-S',
                        required=False, type=str,
                        help='Syslog IP Address')

    parser.add_argument('--syslog-port', '-SP',
                        required=False, type=int,
                        help='Syslog Port')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass(prompt='MVISION Password: ')

    edr = EDR()
    edr.get_threats()
