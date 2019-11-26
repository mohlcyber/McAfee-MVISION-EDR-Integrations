#!/usr/bin/env python3
# Written by mohlcyber v.0.2 (26.11.2019).
# Changelog: added getpass to avoid pw visibility in bash history (thx to secufred)

import getpass
import argparse
import json
import socket

from datetime import datetime
from dxlstreamingclient.channel import Channel, ChannelAuth

# Credentials MVISION EDR
URL = 'https://api.soc.mcafee.com/'

# Topics to subscribe
TOPICS = ['case-mgmt-events', 'BusinessEvents', 'threatEvents']

class EDR():
    def __init__(self):
        self.url = URL
        self.user = args.user
        self.pw = args.password
        self.topics = TOPICS

        self.auth = ChannelAuth(self.url, self.user, self.pw, verify_cert_bundle='')

    def activity_feed(self):
        try:
            with Channel(URL, auth=self.auth, consumer_group='mvisionedr_events', verify_cert_bundle='') as channel:

                def process_callback(payloads):

                    if not payloads == []:
                        for payload in payloads:
                            print(json.dumps(payload))
                            Log().syslogger(json.dumps(payload, separators=(",", ":"), sort_keys=True))

                    return True

                channel.run(process_callback, wait_between_queries=5, topics=self.topics)

        except Exception as e:
            print("Unexpected error: {}".format(e))


class Log():
    def __init__(self):
        self.syslog = args.syslog
        self.port = args.port

    def logger(self, msg):
        t = datetime.now()
        print(msg)
        with open('log.txt', 'a') as logfile:
            logfile.write('{}: {}\n'.format(t, msg))
            logfile.close()

    def syslogger(self, event):
        time = datetime.today().strftime('%b %d %H:%M:%S')
        msg = time + ' MVISION EDR[0]: ' + event

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (self.syslog, self.port))
        sock.close()


if __name__ == "__main__":

    usage = """Usage: mvision_edr_activity_feeds.py -U <USERNAME> -P <PASSWORD> -S <SYSLOG IP> -SP <SYSLOG PORT>"""
    title = 'McAfee EDR Activity Feeds API'
    parser = argparse.ArgumentParser(description=title)
    parser.add_argument('--user', '-U', required=True, type=str)
    parser.add_argument('--password', '-P', required=False, type=str)
    parser.add_argument('--syslog', '-S', required=True, type=str)
    parser.add_argument('--port', '-SP', required=True, type=int)

    args = parser.parse_args()
    if not args.password:
        args.password = getpass.getpass()

    edr = EDR()
    edr.activity_feed()
