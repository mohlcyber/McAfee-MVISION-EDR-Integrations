#Written by mohlcyber v.0.1.

import json
import socket

from datetime import datetime
from dxlstreamingclient.channel import Channel, ChannelAuth

# Credentials MVISION EDR
URL = 'https://api.soc.mcafee.com/'
USER = 'test@test.com'
PW = 'password'

# IP Address of the Syslog server - Receiver
SYSLOG_SERVER = '1.1.1.1'
SYSLOG_PORT = 514

# Topics to subscribe
TOPICS = ['case-mgmt-events', 'BusinessEvents', 'threatEvents']

class EDR():
    def __init__(self):
        self.url = URL
        self.user = USER
        self.pw = PW
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
        sock.sendto(msg.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        sock.close()


if __name__ == "__main__":
    edr = EDR()
    edr.activity_feed()
