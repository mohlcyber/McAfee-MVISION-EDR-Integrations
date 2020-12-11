#!/usr/bin/env python3
# Written by mohlcyber v.0.3 (11.12.2020)
# Script to retrieve all threats from the monitoring dashboard

import sys
import getpass
import argparse
import requests
import time
import json

from datetime import datetime, timedelta


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.base_url = 'soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'soc.mcafee.com'
            
        self.verify = True
        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.days = args.days
        self.limit = args.limit

        self.details = args.details
        self.pattern = '%Y-%m-%dT%H:%M:%S.%fZ'

    def auth(self, creds):
        try:
            res = self.request.get('https://api.' + self.base_url + '/identity/v1/login', auth=creds)

            if res.ok:
                token = res.json()['AuthorizationToken']
                self.request.headers = {'Authorization': 'Bearer {}'.format(token)}
                print('AUTHENTICATION: Successfully authenticated')
            else:
                print('ERROR: Something went wrong during the authentication. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))
                sys.exit()
        except Exception as error:
            print('ERROR: Something went wrong in edr.auth. Error: {}'.format(str(error)))

    def get_threats(self):
        try:
            t_before = (datetime.now() - timedelta(days=self.days)).strftime(self.pattern)
            epoch_before = int(time.mktime(time.strptime(t_before, self.pattern)))

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities

            res = self.request.get('https://api.' + self.base_url + '/ft/api/v2/ft/threats?sort=-rank&filter={0}&from={1}&limit={2}'
                                   .format(json.dumps(filter), str(epoch_before*1000), str(self.limit)))

            if res.ok:
                print('SUCCESS: Successful retrieved threats.')

                res = res.json()

                if self.details == 'True':
                    for threat in res['threats']:
                        # Enrich with detections
                        detections = self.get_detections(threat['id'])
                        threat['url'] = 'https://ui.' + self.base_url + '/monitoring/#/workspace/72,TOTAL_THREATS,{0}'\
                            .format(threat['id'])
                        threat['detections'] = detections

                        # Enrich with trace
                        for detection in threat['detections']['detections']:
                            maGuid = detection['host']['maGuid']
                            traceId = detection['traceId']

                            traces = self.get_trace(maGuid, traceId)
                            detection['traces'] = traces

                print(json.dumps(res))
            else:
                print('ERROR: Something went wrong in retrieving threats. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            print('ERROR: Something went wrong in edr.get_threats. Error: {}'.format(str(error)))

    def get_detections(self, threatid):
        try:
            res = self.request.get('https://api.' + self.base_url + '/ft/api/v2/ft/threats/{0}/detections'
                                   .format(threatid))

            if res.ok:
                return res.json()
            else:
                print('ERROR: Something went wrong in retrieving detections. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            print('ERROR: Something went wrong in edr.get_threatdetections. Error: {}'.format(str(error)))

    def get_trace(self, maGuid, traceId):
        try:
            res = self.request.get('https://api.' + self.base_url +
                                   '/historical/api/v1/traces/main-activity-by-trace-id?maGuid={0}&traceId={1}'
                                   .format(maGuid, traceId))

            if res.ok:
                return(res.json())
            else:
                print('ERROR: Something went wrong in retrieving trace data. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            print('ERROR: Something went wrong in edr.get_trace. Error: {}'.format(str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -DT <DETAILS> -D <DAYS> -L <MAX RESULTS>"""
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

    parser.add_argument('--details', '-DT',
                        required=False, type=str, choices=['True', 'False'],
                        default='True',
                        help='Enrich threat information with detections and affected hosts.')

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
    edr.get_threats()
