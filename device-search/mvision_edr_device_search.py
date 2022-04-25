#!/usr/bin/env python3
# Written by mohlcyber v.1.0 (25.04.2022)
# Script to query device search

import sys
import getpass
import requests
import json
import time
import logging

from argparse import ArgumentParser, RawTextHelpFormatter
from datetime import datetime, timedelta


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
        self.auth(creds)

        self.hostname = args.hostname
        self.days = args.days
        self.limit = args.limit
        self.type = args.type
        self.search = args.search

        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'

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
                'scope': 'mi.user.investigate soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
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

    def get_host(self):
        try:
            query = {"hostname": self.hostname}
            res = self.session.get('https://api.{0}/ft/api/v2/ft/hosts/?filter={1}&fields=hostname,maGuid'
                                   .format(self.base_url,json.dumps(query)))

            if res.ok:
                if res.json()['total'] == 1:
                    for host in res.json()['hosts']:
                        maGuid = host['maGuid']
                        return maGuid
                elif res.json()['total'] > 1:
                    self.logger.error('Too many hosts found with this Hostname. Please be more specfic.')
                    self.logger.error(res.json())
                    exit()
                else:
                    self.logger.error('Could not find a Host with this Hostname.')
                    exit()
            else:
                self.logger.error('Error in edr.get_host(). HTTP {0} - {1}'.format(res.status_code, res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def hist_search(self):
        try:
            t_now = datetime.utcnow().strftime(self.pattern)
            t_before = (datetime.utcnow() - timedelta(days=self.days)).strftime(self.pattern)

            query = {
              "$filter": {
                "$and": [
                  {
                    "detectionDate": {
                      "$gte": t_before
                    }
                  },
                  {
                    "detectionDate": {
                      "$lt": t_now
                    }
                  }
                ],
                "maGuid": self.get_host()
              },
              "$sort": {
                "time": -1
              }
            }

            if self.type is not None:
                query['$filter']['tags'] = '@AC.' + self.type

            if self.search is not None:
                query['$filter']['$and'][0]['$term'] = self.search

            res = self.session.get('https://api.{0}/ltc/api/v1/ltc/query/traces/?query={1}&limit={2}&skip=0'
                                   .format(self.base_url, json.dumps(query), self.limit))

            if res.ok:
                self.logger.info(res.json())
                self.logger.info('Found {0} items.'.format(res.json()['count']))
            else:
                self.logger.error('Error in edr.hist_search(). HTTP {0} - {1}'.format(res.status_code, res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def detect_search(self):
        try:
            t_now = datetime.now().strftime(self.pattern)
            t_before = (datetime.now() - timedelta(days=self.days)).strftime(self.pattern)

            epoch_now = int(time.mktime(time.strptime(t_now, self.pattern)))
            epoch_before = int(time.mktime(time.strptime(t_before, self.pattern)))

            filter = {
                "maGuid": self.get_host()
            }

            severities = ["s1", "s2", "s3", "s4", "s5"]
            if self.type == 'DetectionsAlerts':
                severities.append('s0')

            filter['severities'] = severities

            res = self.session.get('https://api.{0}/mvm/api/v1/middleware/detections?sort=-eventDate&filter={1}&from={2}&to={3}&skip=0&limit={4}&externalOffset=0'
                                   .format(self.base_url, json.dumps(filter), str(epoch_before*1000), str(epoch_now*1000), self.limit))

            if res.ok:
                self.logger.info(res.json())
                if len(res.json()['events']) != 0:
                    self.logger.info('Found {0} items.'.format(len(res.json()['events'])))
                else:
                    self.logger.error('Error in edr.detect_search(). HTTP {0} - {1}'.format(res.status_code, res.text))
                    exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_device_search.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -H <HOSTNAME> -T <TYPE> -ST <SEARCH_TERM> -D <DAYS> -L <MAX RESULTS> -LL <LOG_LEVEL>"""
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

    parser.add_argument('--hostname', '-H',
                        required=True, type=str,
                        help='Hostname to Query')

    parser.add_argument('--type', '-T',
                        required=False, type=str,
                        help='Search Type', choices=[
                            'APICall',
                            'ProcessCreated',
                            'PECreated',
                            'NonPECreated',
                            'ArchiveCreated',
                            'ScriptCreated',
                            'ScriptExecuted',
                            'AdminHackingToolExecuted',
                            'ASEPCreatedOrModified',
                            'ServiceChanged',
                            'NetworkConnection',
                            'DNSQuery',
                            'ScheduledTaskRegistered',
                            'LoginLogout',
                            'LoadedDLLs',
                            'UserAccounts',
                            'WMIActivity',
                            'EPP_Response',
                            'DetectionsAlerts',
                            'Alerts']
                        )

    parser.add_argument('--search', '-ST',
                        required=False, type=str,
                        help='Search Term')

    parser.add_argument('--days', '-D',
                        required=True, type=int,
                        help='How many days back to query')

    parser.add_argument('--limit', '-L',
                        required=True, type=int,
                        help='Limit')

    parser.add_argument('--loglevel', '-LL',
                        required=False, type=str, choices=['INFO', 'DEBUG'], default='INFO',
                        help='Set Log Level')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(prompt='MVISION EDR Client Secret: ')

    edr = EDR()

    if args.type == 'DetectionsAlerts' or args.type == 'Alerts':
        edr.detect_search()
    else:
        edr.hist_search()
