#!/usr/bin/env python3
# Written by mohlcyber v.0.1 (25.04.2022)
# Script to generate client credentials for use in api calls
# This needs to be called only once.
# The generated client credentials must be safely stored for use in api calls
#
# Steps to follow:
#  1. Log on to MVISION EPO Console using your credentials
#  2. Go to "Appliance and Server Registration" page from the menu
#  3. Click on "Add" button
#  4. Choose client type "MVISION Endpoint Detection and Response"
#  5. Enter number of clients (1)
#  6. Click on the "Save" button
#  7. Copy the "Token" value from the table under the section "MVISION Endpoint Detection and Response"
#  8. Pass the token value as the input parameter to this script
#  9. The script will generate the client_id, client_secret and print on the output console
# 10. Use the client_id, client_secret for authentication against the MVISION EDR API

import sys
import requests
import logging
import json

from argparse import ArgumentParser, RawTextHelpFormatter


class EDR():
    def __init__(self):
        self.base_url = 'iam.mcafee-cloud.com/iam/v1.1'
        self.verify = True
        self.logging()

        self.request = requests.Session()

    def logging(self):
        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s;%(levelname)s;%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_client_creds(self, reg_token):
        try:
            iam_url = 'https://{0}/registration'.format(self.base_url)
            payload = {
                'registration_token': reg_token
            }

            res = self.request.post(iam_url, data=payload)

            if res.ok:
                self.logger.info('Successfully generated client credentials for MVISION EDR.')
                self.logger.info('Client_ID: {0} | Client_Secret: {1}'
                                 .format(res.json()['client_id'], res.json()['client_secret']))

                self.logger.debug(json.dumps(res.json()))

                client_creds = {
                    'client_id': res.json()['client_id'],
                    'client_secret': res.json()['client_secret']
                }

                if args.file == 'True':
                    with open('client_creds.json', "w") as outfile:
                        outfile.write(json.dumps(client_creds, indent = 4))

            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                sys.exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python mvision_edr_creds_generator.py -T <REGISTRATION_TOKEN> -F <WRITE_FILE> -L <LOG_LEVEL>"""
    title = 'MVISION EDR Python API'
    parser = ArgumentParser(description=title, usage=usage, formatter_class=RawTextHelpFormatter)

    parser.add_argument('--regtoken', '-T',
                        required=True, type=str,
                        help='Registration Token generated on MVISION EPO UI console')

    parser.add_argument('--file', '-F',
                        required=False, type=str, choices=['True', 'False'],
                        default='False', help='Option to write client creds to file.')

    parser.add_argument('--loglevel', '-L',
                        required=False, type=str, choices=['INFO', 'DEBUG'],
                        default='INFO', help='Option to write client creds to file.')

    args = parser.parse_args()

    edr = EDR()
    edr.generate_client_creds(reg_token=args.regtoken)
