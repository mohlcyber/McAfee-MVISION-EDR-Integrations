#!/usr/bin/env python3
# Written by mohlcyber v.1.0 (25.04.2022)
# Script to retrieve all threats from the monitoring dashboard

import sys
import getpass
import requests
import time
import logging
import json
import os

from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta
from logging.handlers import SysLogHandler


class EDR():
    def __init__(self):
        self.iam_url = 'iam.mcafee-cloud.com/iam/v1.1'
        if args.region == 'EU':
            self.base_url = 'soc.eu-central-1.mcafee.com'
        elif args.region == 'US-W':
            self.base_url = 'soc.mcafee.com'
        elif args.region == 'US-E':
            self.base_url = 'soc.us-east-1.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'soc.ap-southeast-2.mcafee.com'
        elif args.region == 'GOV':
            self.base_url = 'soc.mcafee-gov.com'

        self.logging()

        self.session = requests.Session()
        self.session.verify = True

        if args.proxy == 'True':
            proxies = {
                'https': 'http://1.1.1.1:9090'
            }
            self.session.proxies = proxies

        creds = (args.client_id, args.client_secret)

        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        self.cache_fname = 'cache.log'
        if os.path.isfile(self.cache_fname):
            cache = open(self.cache_fname, 'r')
            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')

            now = datetime.astimezone(datetime.now())
            hours = int(str(now)[-5:].split(':')[0])
            minutes = int(str(now)[-5:].split(':')[1])

            self.last_pulled = (last_detection + timedelta(hours=hours, minutes=minutes, seconds=1)).strftime(self.pattern)
            self.logger.debug('Cache exists. Last detection date UTC: {0}'.format(last_detection))
            self.logger.debug('Pulling newest threats from: {0}'.format(self.last_pulled))
            cache.close()

            self.last_check = (last_detection + timedelta(seconds=1)).strftime(self.pattern)
        else:
            self.logger.debug('Cache does not exists. Pulling data from last 14 days.')
            self.last_pulled = (datetime.now() - timedelta(days=14)).strftime(self.pattern)
            self.last_check = (datetime.now() - timedelta(days=14)).strftime(self.pattern)

        self.limit = '2000'
        self.auth(creds)

    def logging(self):
        # setup the console logger
        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel.upper())
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
            payload = {
                'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
                'grant_type': 'client_credentials',
                'audience': 'mcafee'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                token = res.json()['access_token']
                self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
                self.logger.debug('AUTHENTICATION: Successfully authenticated.')
            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_threats(self):
        try:
            epoch_before = int(time.mktime(time.strptime(self.last_pulled, self.pattern)))

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities

            res = self.session.get(
                'https://api.{0}/ft/api/v2/ft/threats?sort=-lastDetected&filter={1}&from={2}&limit={3}'
                .format(self.base_url, json.dumps(filter), str(epoch_before * 1000), str(self.limit)))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                self.logger.debug('SUCCESS: Successful retrieved threats.')

                res = res.json()
                if len(res['threats']) > 0:
                    cache = open(self.cache_fname, 'w')
                    cache.write(res['threats'][0]['lastDetected'])
                    cache.close()

                    for threat in res['threats']:
                        detections = self.get_detections(threat['id'])
                        threat['url'] = 'https://ui.' + self.base_url + '/monitoring/#/workspace/72,TOTAL_THREATS,{0}'\
                            .format(threat['id'])

                        for detection in detections:
                            threat['detection'] = detection

                            if args.trace == 'True':
                                maGuid = detection['host']['maGuid']
                                traceId = detection['traceId']

                                traces = self.get_trace(maGuid, traceId)
                                detection['traces'] = traces

                            self.logger.info(json.dumps(threat))

                            if args.syslog_ip and args.syslog_port:
                                self.syslog.info(json.dumps(threat, sort_keys=True))
                            if args.file == 'True':
                                if os.path.exists('output') is False:
                                    os.mkdir('output')
                                filename = threat['id']
                                file = open('output/{}'.format(filename), 'w')
                                file.write(json.dumps(threat))
                                file.close()

                else:
                    self.logger.info('No new threats identified. Exiting. {0}'.format(res))
                    exit()
            else:
                self.logger.error('Error in edr.get_threats(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_detections(self, threatId):
        try:
            last_detected = datetime.strptime(self.last_check, self.pattern)

            res = self.session.get('https://api.' + self.base_url + '/ft/api/v2/ft/threats/{0}/detections'
                                   .format(threatId))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                detections = []
                for detection in res.json()['detections']:
                    first_detected = datetime.strptime(detection['firstDetected'], '%Y-%m-%dT%H:%M:%SZ')

                    if first_detected >= last_detected:
                        detections.append(detection)

                return detections
            else:
                self.logger.error('Error in retrieving edr.get_detections(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_trace(self, maGuid, traceId):
        try:
            res = self.session.get('https://api.' + self.base_url +
                                   '/historical/api/v1/traces/main-activity-by-trace-id?maGuid={0}&traceId={1}'
                                   .format(maGuid, traceId))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                return res.json()
            else:
                return {}

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -LL <LOG_LEVEL> -F <FILE WRITE> -SI <SYSLOG IP> -SP <SYSLOG PORT>"""
    title = 'MVISION EDR Python API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US-W', 'US-E', 'SY', 'GOV'])

    parser.add_argument('--client_id', '-C',
                        required=True, type=str,
                        help='MVISION EDR Client ID')

    parser.add_argument('--client_secret', '-S',
                        required=False, type=str,
                        help='MVISION EDR Client Secret')

    parser.add_argument('--trace', '-T',
                        required=False, type=str, choices=['True', 'False'], default='False',
                        help='EXPERIMENTAL: Enrich threat information with trace data')

    parser.add_argument('--loglevel', '-LL',
                        required=False, type=str, choices=['INFO', 'DEBUG'], default='INFO',
                        help='Set Log Level')

    parser.add_argument('--proxy', '-P',
                        required=False, type=str, choices=['True', 'False'], default='False',
                        help='Provide Proxy JSON in line 39')

    parser.add_argument('--file', '-F',
                        required=False, type=str, choices=['True', 'False'], default='False',
                        help='Option to write Threat Events to files')

    parser.add_argument('--syslog-ip', '-SI',
                        required=False, type=str,
                        help='Syslog IP Address')

    parser.add_argument('--syslog-port', '-SP',
                        required=False, type=int,
                        help='Syslog Port')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(prompt='MVISION EDR Client Secret: ')

    edr = EDR()
    edr.get_threats()
