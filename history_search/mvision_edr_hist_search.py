#Written by mohlcyber v.0.1 EDR Python API
#Script to query historical data

import sys
import argparse
import requests
import json

from datetime import datetime, timedelta


class EDR():
    def __init__(self):
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

    def auth(self, creds):
        r = requests.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            print('AUTHENTICATION: Successfully authenticated.')
        else:
            print('ERROR: Something went wrong during the authentication')

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
            t_now = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            t_before = (datetime.now() - timedelta(days=self.days)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')

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

            print(res.json())

        except Exception as e:
            print('ERROR: Something went wrong in edr.hist_search. Error: {}'.format(str(e)))


if __name__ == '__main__':
    usage = """Usage: mvision_edr_remove_file.py -U <username> -P <password>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--user', '-U', required=True, type=str)
    parser.add_argument('--password', '-P', required=True, type=str)
    parser.add_argument('--hostname', '-H', required=True, type=str)
    parser.add_argument('--type', '-T', required=True, type=str)
    parser.add_argument('--days', '-D', required=True, type=int)
    parser.add_argument('--limit', '-L', required=True, type=int)

    args = parser.parse_args()

    type_list = ['ProcessCreated', 'PECreated', 'ScriptCreated', 'AdminHackingToolExecuted', 'ServiceChanged',
                 'NetworkConnection', 'ASEPCreatedOrModified', 'DNSQuery', 'LoadedDLLs', 'UserAccounts']

    if args.type not in type_list:
        print('ERROR: Type is not correctley defined. Type should include on if the following: \n {}'
              .format(str(type_list)))
        sys.exit()

    edr = EDR()
    edr.hist_search()

