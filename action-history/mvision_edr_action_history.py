#!/usr/bin/env python3
# Written by mohlcyber v.0.1 (17.02.2020)
# Script to query action history

import sys
import getpass
import argparse
import requests


class EDR():
    def __init__(self):
        self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        self.verify = True
        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.limit = args.limit

    def auth(self, creds):
        try:
            res = self.request.get(self.base_url + '/identity/v1/login', auth=creds)

            if res.ok:
                token = res.json()['AuthorizationToken']
                self.headers = {'Authorization': 'Bearer {}'.format(token)}
                print('AUTHENTICATION: Successfully authenticated')
            else:
                print('ERROR: Something went wrong during the authentication. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))

    def action_history(self):
        # Additional filters are available: /?$sortBy=creationDate&$sortDirection=desc&$offset=0

        try:
            res = self.request.get(self.base_url + '/remediation/api/v1/actions/?$limit={0}'.format(str(self.limit)),
                                   headers=self.headers)
            if res.ok:
                print('SUCCESS: Successful retrieved action history')
                print(res.text)
            else:
                print('ERROR: Something went wrong in retrieving the action history. Error: {0} - {1}'
                      .format(str(res.status_code), res.text))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_action_history.py -U <USERNAME> -P <PASSWORD> -L <MAX RESULTS>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--user', '-U', required=True, type=str)
    parser.add_argument('--password', '-P', required=False, type=str)
    parser.add_argument('--limit', '-L', required=True, type=int)

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    edr = EDR()
    edr.action_history()