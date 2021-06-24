#!/usr/bin/env python3
# Written by mohlcyber v.0.2 (24.06.2021)
# Script to query action history

import sys
import getpass
import argparse
import requests
import json
import logging

logger = logging.getLogger('logs')
logger.setLevel('DEBUG')
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


class EDR():
    def __init__(self):
        if args.region == 'EU':
            self.base_url = 'soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'soc.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'soc.ap-southeast-2.mcafee.com'

        self.verify = True
        self.session = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.limit = args.limit

    def auth(self, creds):
        try:
            res = self.session.get('https://api.' + self.base_url + '/identity/v1/login', auth=creds)

            if res.ok:
                token = res.json()['AuthorizationToken']
                headers = {'Authorization': 'Bearer {}'.format(token)}
                self.session.headers.update(headers)
                logger.info('AUTHENTICATION: Successfully authenticated')
            else:
                logger.error('edr.auth(). Error: {0} - {1}'.format(str(res.status_code), res.text))
                sys.exit()
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))

    def action_history(self):
        # Additional filters are available: /?$sortBy=creationDate&$sortDirection=desc&$offset=0

        try:
            res = self.session.get('https://api.' + self.base_url + '/remediation/api/v1/actions/?$limit={0}'
                                   .format(str(self.limit)))
            if res.ok:
                logger.info('SUCCESS: Successful retrieved action history')
                logger.info(json.dumps(res.json()))
            else:
                logger.error('edr.action_history. Error: {0} - {1}'.format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_action_history.py -R <REGION> -U <USERNAME> -P <PASSWORD> -L <MAX RESULTS>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--region', '-R', required=True, type=str)
    parser.add_argument('--user', '-U', required=True, type=str)
    parser.add_argument('--password', '-P', required=False, type=str)
    parser.add_argument('--limit', '-L', required=True, type=int)

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    edr = EDR()
    edr.action_history()
