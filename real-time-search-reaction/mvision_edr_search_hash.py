#!/usr/bin/env python3
# Written by mohlcyber v.1.0 (25.04.2022)
# based on a hash, script will automatically launch MVISION EDR query

import sys
import getpass
import time
import requests
import logging
import json

from argparse import ArgumentParser, RawTextHelpFormatter


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

        self.hash = args.hash

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
                'scope': 'mi.user.investigate soc.act.tg soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
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

    def search(self):
        try:
            queryId = None

            if len(str(self.hash)) == 32:
                type = 'md5'
            elif len(str(self.hash)) == 40:
                type = 'sha1'
            elif len(str(self.hash)) == 64:
                type = 'sha256'
            else:
                self.logger.error('Something went wrong with the Hash input. Please use MD5, SHA1 or SHA256')
                sys.exit()

            payload = {
                "projections": [
                    {
                        "name": "HostInfo",
                        "outputs": ["hostname", "ip_address"]
                    }, {
                        "name": "Files",
                        "outputs": ["name", str(type), "status", "full_name"]
                    }
                ],
                "condition": {
                    "or": [{
                        "and": [{
                            "name": "Files",
                            "output": str(type),
                            "op": "EQUALS",
                            "value": str(self.hash)
                        }]
                    }]
                }
            }

            res = self.session.post('https://api.{0}/active-response/api/v1/searches'.format(self.base_url), json=payload)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                queryId = res.json()['id']
                self.logger.info('MVISION EDR search got started successfully')
            else:
                self.logger.error('Error in edr.search(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

            return queryId

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def search_status(self, queryId):
        try:
            status = False
            res = self.session.get('https://api.{0}/active-response/api/v1/searches/{1}/status'.format(self.base_url, str(queryId)))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                if res.json()['status'] == 'FINISHED':
                    status = True
                else:
                    self.logger.info('Search still in process. Status: {}'.format(res.json()['status']))
            return status
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def search_result(self, queryId):
        try:
            res = self.session.get('https://api.{0}/active-response/api/v1/searches/{1}/results'.format(self.base_url, str(queryId)))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                try:
                    items = res.json()['totalItems']
                    react_summary = []
                    for item in res.json()['items']:
                        if item['output']['Files|status'] != 'deleted':
                            react_dict = {}
                            react_dict[item['id']] = item['output']['Files|full_name']
                            react_summary.append(react_dict)

                    self.logger.debug(json.dumps(res.json()))
                    self.logger.info('MVISION EDR search got {0} responses for this hash. {1} '
                                'of them with the file status CURRENT.'.format(items, len(react_summary)))

                    return react_summary

                except Exception as e:
                    self.logger.error('Something went wrong to retrieve the results. Error: {}'.format(e))
                    exit()
            else:
                self.logger.error('Error in edr.search_result(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def get_reactions(self):
        try:
            res = self.session.get('https://api.{0}/active-response/api/v1/catalog/reactions'.format(self.base_url))

            if res.ok:
                return res.json()
            else:
                self.logger.error('Error in edr.get_reactions(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def reaction_execution(self, queryId, systemId, filePath):
        try:
            payload = {
                "action":"removeFile",
                "searchResultsArguments": {
                    "searchId": int(queryId),
                    "rowsIds": [str(systemId)],
                    "arguments": {}
                },
                "provider": "AR",
                "actionInputs": [
                    {
                        "name": "full_name",
                        "value": str(filePath)
                    }
                ]
            }

            res = self.session.post('https://api.{0}/remediation/api/v1/actions/search-results-actions'.format(self.base_url),
                                    json=payload)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                rid = res.json()['id']
                self.logger.info('MVISION EDR reaction got executed successfully')
                return rid
            else:
                self.logger.error('Error in edr.reaction_execution(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def main(self):
        try:
            # Retrieve all reactions
            # reactions = self.get_reactions()
            # self.logger.info(json.dumps(reactions))
            # sys.exit()

            queryId = self.search()
            if queryId is None:
                exit()

            while self.search_status(queryId) is False:
                time.sleep(30)

            results = self.search_result(queryId)
            if len(results) == 0:
                self.logger.info('All Files deleted on Systems')
                exit()

            if args.reaction == 'True':
                for result in results:
                    for systemId, filePath in result.items():
                        reaction_id = self.reaction_execution(queryId, systemId, filePath)

                        if reaction_id is None:
                            self.logger.error('Could not create new MVISION EDR reaction')

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """Usage: python mvision_edr_search_hash.py -C <CLIENT_ID> -S <CLIENT_SECRET> -H <HASH>"""
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

    parser.add_argument('--hash', '-H', required=True,
                        type=str, default='Hash to search for. Can be MD5, SHA1, SHA256')

    parser.add_argument('--reaction', '-RE', required=False,
                        type=str, choices=['True', 'False'],
                        default='False', help='Delete Files that got identified.')

    parser.add_argument('--loglevel', '-L', required=False,
                        type=str, choices=['INFO', 'DEBUG'],
                        default='INFO', help='Specify log level.')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(prompt='MVISION EDR Client Secret: ')

    EDR().main()
