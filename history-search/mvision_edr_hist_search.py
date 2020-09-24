#!/usr/bin/env python3
# Written by mohlcyber v.0.4 (24.09.2020)
# Script to query historical data

import sys
import getpass
import argparse
import requests
import json
import time

from datetime import datetime, timedelta


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'https://api.soc.mcafee.com'

        self.verify = True
        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.hostname = args.hostname
        self.days = args.days
        self.limit = args.limit
        self.type = args.type

        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'

    def auth(self, creds):
        r = requests.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            print('AUTHENTICATION: Successfully authenticated.')
        else:
            print('ERROR: Something went wrong during the authentication')
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
                print('ERROR: To many hosts found with this Hostname. Please be more specfic.')
                print(res.json())
                sys.exit()
            else:
                print('ERROR: Could not find a Host with this Hostname.')
                sys.exit()

        except Exception as e:
            print('ERROR: Something went wrong in edr.get_hosts. Error: {}'.format(str(e)))

    def hist_search(self):
        try:
            t_now = datetime.now().strftime(self.pattern)
            t_before = (datetime.now() - timedelta(days=self.days)).strftime(self.pattern)

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
                "maGuid": self.get_host(),
                "tags": "@AC."+self.type
              },
              "$sort": {
                "time": -1
              }
            }

            res = self.request.get(self.base_url + '/ltc/api/v1/ltc/query/traces/?query={}&limit={}&skip=0'
                                   .format(json.dumps(query), self.limit),
                                    headers=self.headers)

            if res.status_code != 200:
                print('ERROR: edr.detect_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                print(res.json())

        except Exception as error:
            print('ERROR: Something went wrong in edr.hist_search. Error: {}'.format(str(error)))

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

            res = self.request.get(self.base_url + '/mvm/api/v1/middleware/detections?sort=-eventDate&filter={0}&from={1}&to={2}&skip=0&limit={3}&externalOffset=0'
                                   .format(json.dumps(filter), str(epoch_before*1000), str(epoch_now*1000), self.limit),
                                   headers=self.headers)

            if res.status_code != 200:
                print('ERROR: edr.detect_search - {0} - {1}'.format(str(res.status_code), res.text))
            else:
                print(res.json())

        except Exception as error:
            print('ERROR: Something went wrong in edr.detect_search. Error: {}'.format(str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_hist_search.py -R <REGION> -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> -T <SEARCHTYPE> -D <DAYS> -L <MAX RESULTS>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)

    parser.add_argument('--region', '-R',
                        required=True, type=str,
                        help='MVISION EDR Tenant Location', choices=['EU', 'US'])

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
                        required=True, type=str,
                        help='Search Type', choices=[
                            'ProcessCreated',
                            'PECreated',
                            'ArchiveCreated',
                            'ScriptCreated',
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
                            'DetectionsAlerts',
                            'Alerts']
                        )

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
