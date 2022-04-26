#!/usr/bin/env python3
# Written by mohlcyber v.1.0 (25.04.2022)
# Script to retrieve all threats from the monitoring dashboard and stop the related process

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
        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel.upper())
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def auth(self, creds):
        try:
            payload = {
                'scope': 'mi.user.investigate soc.act.tg soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr soc.internal',
                'grant_type': 'client_credentials',
                'audience': 'mcafee'
            }

            self.session.headers = {
                'Content-Type': 'application/json'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), data=payload, auth=creds)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                token = res.json()['access_token']
                self.session.headers.update({'Authorization': 'Bearer {}'.format(token)})
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

                        pname = threat['name']
                        tid = threat['id']
                        caseid = self.get_case(pname, tid)
                        affhids = self.get_affhosts(tid)

                        for hid in affhids:
                            self.exec_reaction(caseid, tid, hid)

                        #self.logger.info(json.dumps(threat))

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

    def get_case(self, pName, tId):
        try:
            data = {
                'processName': pName,
                'threatId': int(tId)
            }

            res = self.session.post('https://api.{0}/case-mgmt/v1/cases/threats'.format(self.base_url), json=data)

            if res.ok:
                caseId = str(res.json()['_links']['self']['href']).split('/')
                return caseId[4]
            else:
                self.logger.error('Error in retrieving edr.get_case(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_affhosts(self, tid):
        try:
            afids = []
            res = self.session.get('https://api.{0}/ft/api/v2/ft/threats/{1}/affectedhosts'.format(self.base_url, str(tid)))

            if res.ok:
                for host in res.json()['affectedHosts']:
                    afids.append(host['id'])

                return afids

            else:
                self.logger.error('Error in retrieving edr.get_affectedhosts(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def exec_reaction(self, caseId, tid, hid):
        try:
            data = {
                'action': 'StopProcess', # options [StopProcess, StopAndRemove, QuarantineHost, UnquarantineHost]
                'caseId': str(caseId),
                'threatActionArguments': {
                    'threatId': str(tid),
                    'targetAffectedHosts': [
                        str(hid)
                    ]
                }
            }

            res = self.session.post('https://api.{0}/remediation/api/v1/actions/threat-actions'.format(self.base_url),
                                    data=json.dumps(data))

            if res.ok:
                self.logger.info('Successfully executed reaction for threatId {}'.format(tid))
                self.logger.info(res.text)
            else:
                self.logger.error('Error in retrieving edr.exec_reaction(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                #sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -LL <LOG_LEVEL> """
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

    parser.add_argument('--loglevel', '-LL',
                        required=False, type=str, choices=['INFO', 'DEBUG'], default='INFO',
                        help='Set Log Level')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(prompt='MVISION EDR Client Secret: ')

    edr = EDR()
    edr.get_threats()
