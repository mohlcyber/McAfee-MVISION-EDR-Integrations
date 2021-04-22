#!/usr/bin/env python3
# Written by mohlcyber v.0.2 (26.11.2019)
# based on a hash script will automatically launch MVISION EDR query

import sys
import getpass
import time
import requests
import logging
import json

from argparse import ArgumentParser, RawTextHelpFormatter


class EDR():
    def __init__(self):
        self.logger = logging.getLogger('logs')
        loglevel = args.loglevel
        self.logger.setLevel(loglevel)
        ch = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if args.region == 'EU':
            self.base_url = 'https://api.soc.eu-central-1.mcafee.com'
        elif args.region == 'US':
            self.base_url = 'https://api.soc.mcafee.com'
        elif args.region == 'SY':
            self.base_url = 'https://api.soc.ap-southeast-2.mcafee.com'

        self.verify = True
        self.request = requests.Session()

        user = args.user
        pw = args.password
        creds = (user, pw)
        self.auth(creds)

        self.hash = args.hash

    def auth(self, creds):
        r = self.request.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            headers = {'Authorization': 'Bearer {}'.format(token)}
            self.request.headers.update(headers)
            self.logger.info('Successfully authenticated.')
        else:
            self.logger.error('Something went wrong during the authentication')
            sys.exit()

    def search(self):
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

        res = self.request.post(self.base_url + '/active-response/api/v1/searches', json=payload)
        try:
            if res.status_code == 200:
                queryId = res.json()['id']
                self.logger.info('MVISION EDR search got started successfully')
            else:
                self.logger.error('Could not find the query ID. Error {} - {}'.format(str(res.status_code), res.text))
        except Exception as e:
            self.logger.error('Could not find the query ID. Error: {}'.format(e))
            sys.exit()

        return queryId

    def search_status(self, queryId):
        status = False
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/status'.format(str(queryId)))
        if res.status_code == 200:
            if res.json()['status'] == 'FINISHED':
                status = True
            else:
                self.logger.info('Search still in process. Status: {}'.format(res.json()['status']))
        return status

    def search_result(self, queryId):
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/results'.format(str(queryId)))
        if res.status_code == 200:
            try:
                items = res.json()['totalItems']

                react_summary = []
                for item in res.json()['items']:
                    if item['output']['Files|status'] != 'deleted':
                        react_dict = {}
                        react_dict[item['id']] = item['output']['Files|full_name']
                        react_summary.append(react_dict)

                self.logger.debug(json.dumps(res.json()))
                self.logger.info('MVISION EDR search got {} responses for this hash. {} '
                            'of them with the file status CURRENT.'.format(items, len(react_summary)))

                return react_summary

            except Exception as e:
                self.logger.error('Something went wrong to retrieve the results. Error: {}'.format(e))
                sys.exit()
        else:
            self.logger.error('Something went wrong to retrieve the results.')
            sys.exit()

    def get_reactions(self):
        res = self.request.get(self.base_url + '/active-response/api/v1/catalog/reactions')

        if res.status_code == 200:
            return res.json()
        else:
            self.logger.error('Something went wrong to retrieve reactions.: {0}'.format(str(res.text)))

    def reaction_execution(self, queryId, systemId, filePath):
        reactionId = None

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

        res = self.request.post(self.base_url + '/remediation/api/v1/actions/search-results-actions', json=payload)

        if res.status_code == 201:
            try:
                reactionId = res.json()['id']
                self.logger.info('MVISION EDR reaction got executed successfully')
            except Exception as e:
                self.logger.error('Something went wrong to create reaction. Error: {}'.format(e))
                sys.exit()

        return reactionId

    def main(self):
        # Retrieve all reactions
        # reactions = self.get_reactions()
        # self.logger.info(json.dumps(reactions))
        # sys.exit()

        queryId = self.search()
        if queryId is None:
            sys.exit()

        while self.search_status(queryId) is False:
            time.sleep(30)

        results = self.search_result(queryId)
        if results == []:
            self.logger.info('All Files deleted on Systems')
            sys.exit()

        if args.reaction == 'True':
            for result in results:
                for systemId, filePath in result.items():
                    reaction_id = self.reaction_execution(queryId, systemId, filePath)

                    if reaction_id is None:
                        self.logger.error('Could not create new MVISION EDR reaction')


if __name__ == '__main__':
    usage = """Usage: mvision_edr_search_file.py -U <username> -P <password> -H <hash>"""
    title = 'McAfee EDR Python API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R', required=True,
                        choices=['EU', 'US', 'SY'], type=str,
                        help='MVISION EDR Tenant Region')

    parser.add_argument('--user', '-U', required=True,
                        type=str, help='MVISION EDR User Account')

    parser.add_argument('--password', '-P', required=False,
                        type=str, help='MVISION EDR Password')

    parser.add_argument('--hash', '-H', required=True,
                        type=str, default='Hash to search for. Can be MD5, SHA1, SHA256')

    parser.add_argument('--reaction', '-RE', required=False,
                        type=str, choices=['True', 'False'],
                        default='False', help='Delete Files that got identified.')

    parser.add_argument('--loglevel', '-L', required=False,
                        type=str, choices=['INFO', 'DEBUG'],
                        default='INFO', help='Specify log level.')

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    EDR().main()