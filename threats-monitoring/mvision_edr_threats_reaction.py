#!/usr/bin/env python3
# Written by mohlcyber v.0.1 (18.11.2021)
# Script to retrieve threats from the monitoring dashboard and stop the related process

import sys
import getpass
import requests
import time
import logging
import json
import os

from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta


class EDR():
    def __init__(self):
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

        self.verify = True
        self.logging()

        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)

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
            self.logger.debug('Cache does not exists. Pulling data from last 7 days.')
            self.last_pulled = (datetime.now() - timedelta(days=7)).strftime(self.pattern)
            self.last_check = (datetime.now() - timedelta(days=7)).strftime(self.pattern)

        self.limit = args.limit

        self.auth(creds)

    def logging(self):
        self.logger = logging.getLogger('logs')
        self.logger.setLevel('DEBUG')
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def auth(self, creds):
        try:
            res = self.request.get('https://api.' + self.base_url + '/identity/v1/login', auth=creds)

            if res.ok:
                token = res.json()['AuthorizationToken']
                self.request.headers = {
                    'Authorization': 'Bearer {}'.format(token),
                    'Content-Type': 'application/json'
                }
                self.logger.debug('Successfully authenticated')
            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_threats(self):
        try:
            epoch_before = int(time.mktime(time.strptime(self.last_pulled, self.pattern)))
            self.timer = str(epoch_before * 1000)

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities

            res = self.request.get(
                'https://api.{0}/ft/api/v2/ft/threats?sort=-lastDetected&filter={1}&from={2}&limit={3}'
                .format(self.base_url, json.dumps(filter), self.timer, str(self.limit)))

            if res.ok:
                self.logger.info('SUCCESS: Successful retrieved threats.')

                res = res.json()
                if len(res['threats']) > 0:
                    cache = open(self.cache_fname, 'w')
                    cache.write(res['threats'][0]['lastDetected'])
                    cache.close()

                    for threat in res['threats']:
                        # Enrich with detections
                        detections = self.get_detections(threat['id'])
                        threat['url'] = 'https://ui.' + self.base_url + '/monitoring/#/workspace/72,TOTAL_THREATS,{0}'\
                            .format(threat['id'])

                        for detection in detections:
                            threat['detection'] = detection

                            pName = threat['name']
                            tId = threat['id']
                            caseId = self.get_case(pName, tId)
                            systemId = detection['id']

                            self.exec_reaction(caseId, tId, systemId)

                            #self.logger.info(json.dumps(threat))

                else:
                    self.logger.info('No new threats identified. Exiting. {0}'.format(res))
                    sys.exit()
            else:
                self.logger.error('Error in edr.get_threats(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_detections(self, threatId):
        try:
            last_detected = datetime.strptime(self.last_check, self.pattern)

            params = {
                'limit': '30',
                'sort': '-rank',
                'skip': '0'
            }

            res = self.request.get('https://api.{0}/ft/api/v2/ft/threats/{1}/affectedhosts'
                                   .format(self.base_url, threatId), params=params)

            if res.ok:
                detections = []
                for detection in res.json()['affectedHosts']:
                    first_detected = datetime.strptime(detection['firstDetected'], '%Y-%m-%dT%H:%M:%SZ')

                    if first_detected >= last_detected:
                        detections.append(detection)

                return detections
            else:
                self.logger.error('Error in retrieving edr.get_detections(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

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

            res = self.request.post('https://api.{0}/case-mgmt/v1/cases/threats'.format(self.base_url), json=data)

            if res.ok:
                caseId = str(res.json()['_links']['self']['href']).split('/')
                return caseId[4]
            else:
                self.logger.error('Error in retrieving edr.get_case(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def exec_reaction(self, caseId, tId, hId):
        try:
            data = {
                'action': 'StopProcess', # alternative - StopAndRemove and Quarantine
                'caseId': str(caseId),
                'threatActionArguments': {
                    'threatId': str(tId),
                    'targetAffectedHosts': [
                        str(hId)
                    ]
                }
            }

            res = self.request.post('https://api.{0}/remediation/api/v1/actions/threat-actions'.format(self.base_url),
                                    data=json.dumps(data))

            if res.ok:
                self.logger.info('Successfully executed reaction for threatId {}'.format(tId))
                self.logger.info(res.text)
            else:
                self.logger.error('Error in retrieving edr.exec_reaction(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -L <MAX RESULTS> -S <SYSLOG IP> -SP <SYSLOG PORT>"""
    title = 'McAfee EDR Python API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US-W', 'US-E', 'SY', 'GOV'])

    parser.add_argument('--user', '-U',
                        required=True, type=str,
                        help='MVISION EDR Username')

    parser.add_argument('--password', '-P',
                        required=False, type=str,
                        help='MVISION EDR Password')

    parser.add_argument('--limit', '-L',
                        required=True, type=int,
                        help='Maximum number of returned items')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass(prompt='MVISION Password: ')

    edr = EDR()
    edr.get_threats()
