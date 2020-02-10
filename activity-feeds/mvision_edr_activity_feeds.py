#!/usr/bin/env python3
# Written by mohlcyber v.0.3 (10.02.2020)

import getpass
import argparse
import json
import socket
import logging

from datetime import datetime
from dxlstreamingclient.channel import Channel, ChannelAuth

# Credentials MVISION EDR
URL = 'https://api.soc.eu-central-1.mcafee.com/'

# Topics to subscribe
TOPICS = ['case-mgmt-events', 'BusinessEvents', 'threatEvents']

class EDR():
    def __init__(self):
        self.url = URL
        self.user = args.user
        self.pw = args.password
        self.auth = ChannelAuth(self.url, self.user, self.pw, verify_cert_bundle='')

        loglevel = args.loglevel

        logging.basicConfig(level=getattr(logging, loglevel.upper(), None))
        logger = logging.getLogger()
        ch = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    def activity_feed(self):
        logging.info("Starting event loop...")
        try:
            with Channel(self.url, auth=self.auth, consumer_group='mvisionedr_events', verify_cert_bundle='') as channel:
                def process_callback(payloads):
                    if not payloads == []:
                        for payload in payloads:
                            print(json.dumps(payload))
                            Log().syslogger(json.dumps(payload, separators=(",", ":"), sort_keys=True))

                    return True

                channel.run(process_callback, wait_between_queries=5, topics=TOPICS)

        except Exception as e:
            logging.error("Unexpected error: {}".format(e))


class Log():
    def __init__(self):
        self.syslog = args.syslog
        self.port = args.port

    def syslogger(self, event):
        time = datetime.today().strftime('%b %d %H:%M:%S')
        msg = time + ' MVISION EDR[0]: ' + event

        with open('activity_feeds.txt', 'a') as logfile:
            logfile.write('{}: {}\n'.format(time, msg))
            logfile.close()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (self.syslog, self.port))
        sock.close()


if __name__ == "__main__":

    usage = """Usage: mvision_edr_activity_feeds.py -U <USERNAME> -P <PASSWORD> -S <SYSLOG IP> -SP <SYSLOG PORT>"""
    title = 'McAfee EDR Activity Feeds API'
    parser = argparse.ArgumentParser(description=title)

    parser.add_argument('--user', '-U',
                        required=True, type=str,
                        help='MVISION EDR Username')

    parser.add_argument('--password', '-P',
                        required=False, type=str,
                        help='MVISION EDR Password')

    parser.add_argument('--syslog', '-S',
                        required=True, type=str,
                        help='Syslog Server IP or Hostname')

    parser.add_argument('--port', '-SP',
                        required=True, type=int,
                        help='Syslog Port')

    parser.add_argument('--loglevel', '-L',
                        required=False, type=str,
                        default='info', choices=['critical', 'error', 'warning',
                                 'info', 'debug', 'notset'])

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    edr = EDR()
    edr.activity_feed()
