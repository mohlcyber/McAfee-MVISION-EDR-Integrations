#!/usr/bin/env python3
# Written by mohlcyber v.0.6 (05.04.2021)
# Script to query historical data

import sys
import getpass
import argparse
import requests
import json
import time
import logging

from datetime import datetime, timedelta


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'https://api.soc.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'https://api.soc.ap-southeast-2.mcafee.com'

        self.verify = True

        self.logger = logging.getLogger('logs')
        self.logger.setLevel('DEBUG')
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.hostname = args.hostname
        self.days = args.days
        self.limit = args.limit
        self.type = args.type
        self.search = args.search

        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'

    def auth(self, creds):
        r = requests.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            self.logger.debug('AUTHENTICATION: Successfully authenticated.')
        else:
            self.logger.error('Something went wrong during the authentication')
            sys.exit()

    def get_host(self):
        try:
            query = {"hostname": self.hostname}
            res = self.request.get(self.base_url + '/ft/api/v2/ft/hosts/?filter={}&fields=hostname,maGuid'
                                   .format(json.dumps(query)),
                                   headers=self.headers)

            if res.json()['total'] == 1:
                for host in res.json()['hosts']:
                    maGuid = host['maGuid']
                    return maGuid
            elif res.json()['total'] > 1:
                self.logger.error('Too many hosts found with this Hostname. Please be more specfic.')
                self.logger.error(res.json())
                sys.exit()
            else:
                self.logger.error('Could not find a Host with this Hostname.')
                sys.exit()

        except Exception as error:
            self.logger.error('Error in edr.get_hosts. Error: {}'.format(str(error)))

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

            res = self.request.get(self.base_url + '/ltc/api/v1/ltc/query/traces/?query={}&limit={}&skip=0'
                                   .format(json.dumps(query), self.limit),
                                   headers=self.headers)

            if res.status_code != 200:
                self.logger.error('edr.detect_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                self.logger.info(res.json())
                self.logger.info('Found {0} items.'.format(res.json()['count']))

        except Exception as error:
            self.logger.error('Error in edr.hist_search. Error: {}'.format(str(error)))

    def detect_search(self):
        try:
            t_now = datetime.utcnow().strftime(self.pattern)
            t_before = (datetime.utcnow() - timedelta(days=self.days)).strftime(self.pattern)

            epoch_now = int(time.mktime(time.strptime(t_now, self.pattern)))
            epoch_before = int(time.mktime(time.strptime(t_before, self.pattern)))

            filter = {
                "maGuid": self.get_host()
            }

            severities = ["s1", "s2", "s3", "s4", "s5"]
            if self.type == 'DetectionsAlerts':
                severities.append('s0')

            filter['severities'] = severities

            res = self.request.get(self.base_url + '/mvm/api/v1/middleware/detections?sort=-eventDate&filter={0}&from={1}&to={2}&skip=0&limit={3}&externalOffset=0'
                                   .format(json.dumps(filter), str(epoch_before*1000), str(epoch_now*1000), self.limit),
                                   headers=self.headers)

            if res.status_code != 200:
                self.logger.error('Error in edr.detect_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                self.logger.info(res.json())
                self.logger.info('Found {0} items.'.format(res.json()['count']))

        except Exception as error:
            self.logger.error('Error in edr.detect_search. Error: {}'.format(str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_hist_search.py -R <REGION> -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> """\
            """-T <TYPE> -S <SEARCH> -D <DAYS> -L <MAX RESULTS>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US', 'SY'])

    parser.add_argument('--user', '-U',
                        required=True, type=str,
                        help='MVISION EDR Username')

    parser.add_argument('--password', '-P',
                        required=False, type=str,
                        help='MVISION EDR Password')

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

    parser.add_argument('--search', '-S',
                        required=False, type=str,
                        help='Search Term')

    parser.add_argument('--days', '-D',
                        required=True, type=int,
                        help='How many days back to query')

    parser.add_argument('--limit', '-L',
                        required=True, type=int,
                        help='Limit')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    edr = EDR()

    if args.type == 'DetectionsAlerts' or args.type == 'Alerts':
        edr.detect_search()
    else:
        edr.hist_search()
