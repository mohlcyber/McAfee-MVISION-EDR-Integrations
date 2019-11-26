#!/usr/bin/env python3
# Written by mohlcyber v.0.2 (26.11.2019)
# based on a hash script will automatically launch MVISION EDR query and tries to delete files (RemoveFile)
# Changelog: added getpass to avoid pw visibility in bash history (thx to secufred)

import sys
import getpass
import time
import argparse
import requests


class EDR():
    def __init__(self):
        self.base_url = 'https://api.soc.mcafee.com'
        self.verify = True
        self.request = requests.Session()

        user = args.user
        creds = (user, PW)
        self.auth(creds)

        self.query = args.hash

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

    def search(self):
        queryId = None

        if len(str(self.query)) == 32:
            type = 'md5'
        elif len(str(self.query)) == 40:
            type = 'sha1'
        elif len(str(self.query)) == 64:
            type = 'sha256'
        else:
            print('ERROR: Something went wrong with the Hash input')
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
                        "value": str(self.query)
                    }]
                }]
            }
        }

        res = self.request.post(self.base_url + '/active-response/api/v1/searches',
                                headers=self.headers,
                                json=payload)
        try:
            if res.status_code == 200:
                queryId = res.json()['id']
                print('SEARCH: MVISION EDR search got started successfully')
            else:
                print('ERROR: Could not find the query ID.')
        except Exception as e:
            print('ERROR: Could not find the query ID. Error: {}'.format(e))
            sys.exit()

        return queryId

    def search_status(self, queryId):
        status = False
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/status'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            if res.json()['status'] == 'FINISHED':
                status = True
            else:
                print('STATUS: Search still in process. Status: {}'.format(res.json()['status']))
        return status

    def search_result(self, queryId):
        res = self.request.get(self.base_url + '/active-response/api/v1/searches/{}/results'.format(str(queryId)), headers=self.headers)
        if res.status_code == 200:
            try:
                items = res.json()['totalItems']

                react_summary = []
                for item in res.json()['items']:
                    if item['output']['Files|status'] != 'deleted':
                        react_dict = {}
                        react_dict[item['id']] = item['output']['Files|full_name']
                        react_summary.append(react_dict)

                print('RESULT: MVISION EDR found {} System/s with this hash. {} of them with the file status CURRENT.'.format(items, len(react_summary)))

                return react_summary

            except Exception as e:
                print('ERROR: Something went wrong to retrieve the results. Error: {}'.format(e))
                sys.exit()
        else:
            print('ERROR: Something went wrong to retrieve the results.')
            sys.exit()

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

        res = self.request.post(self.base_url + '/remediation/api/v1/actions/search-results-actions',
                              headers=self.headers,
                              json=payload)

        if res.status_code == 201:
            try:
                reactionId = res.json()['id']
                print('REACTION: MVISION EDR reaction got executed successfully')
            except Exception as e:
                print('ERROR: Something went wrong to create reaction. Error: {}'.format(e))
                sys.exit()

        return reactionId

    def reaction_status(self, reactionId):
        done = False
        res = self.request.get(self.base_url + '/remediation/api/v1/actions/{}/status'.format(str(reactionId)),
                               headers=self.headers)

        if res.status_code == 200:
            try:
                print('STATUS: MVISION EDR Reaction status is {}.'.format(res.json()['status']))
                if res.json()['status'] == 'COMPLETED':
                    done = True
            except Exception as e:
                print('ERROR: Could not get the search ID. Error: {}'.format(e))
                sys.exit()

        return done


if __name__ == '__main__':
    usage = """Usage: mvision_edr_remove_file.py -U <username> -H <hash>"""
    title = 'McAfee EDR Python API'
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--user', '-U', required=True, type=str)
    parser.add_argument('--hash', '-H', required=True, type=str)

    args = parser.parse_args()
    try:
        PW = getpass.getpass()
    except Exception as error:
        print('Error', error)
        sys.exit()

    edr = EDR()
    queryId = edr.search()
    if queryId is None:
        sys.exit()

    while edr.search_status(queryId) is False:
        time.sleep(10)

    results = edr.search_result(queryId)
    if results == []:
        print('INFO: All Files deleted on Systems')
        sys.exit()

    for result in results:
        for systemId, filePath in result.items():
            reaction_id = edr.reaction_execution(queryId, systemId, filePath)

            if reaction_id is None:
                print('ERROR: Could not create new MVISION EDR reaction')

            while edr.reaction_status(reaction_id) is False:
                print('STATUS: Waiting for 5 seconds to check again.')
                time.sleep(5)