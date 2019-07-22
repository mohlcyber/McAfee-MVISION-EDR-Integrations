# v.0.0.1 by mohlcyber
# inspired from McAfee OpenDXL Streaming libraries

import os
import requests
import json
import base64
import signal
import time
import mvision_edr_globals
import socket
from datetime import datetime


def signal_handler(*_):
    mvision_edr_globals.interrupted = True
    print("Attempting to exit gracefully")

signal.signal(signal.SIGINT, signal_handler)

# Credentials MVISION EDR
EDR_USER = 'email@email.com'
EDR_PW = 'password'

# IP Address of the Syslog server - Receiver
SYSLOG_SERVER = 'ip address'
SYSLOG_PORT = 514 

# Topics to subscribe
TOPICS = ['case-mgmt-events', 'BusinessEvents', 'threatEvents']


class MVISIONEDR():
    def __init__(self):
        self.base_url = 'https://api.soc.mcafee.com'
        creds = (EDR_USER, EDR_PW)
        self.path = '/databus/consumer-service/v1/'
        self.timeout = 300000
        self.request = requests.Session()
        self._auth(creds)

    def _auth(self, creds):
        r = self.request.get(self.base_url + '/identity/v1/login', auth=creds)
        res = r.json()

        if r.status_code == 200:
            self.token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(self.token)}
            Log().logger('Successfully authenticated.')
        else:
            Log().logger('Something went wrong during the authentication')

    def create(self):
        payload = {
            'consumerGroup': 'mcafee_investigator_events',
            'configs': {
                'session.timeout.ms': str(self.timeout),
                'request.timeout.ms': str(self.timeout + 10),
                'enable.auto.commit': 'true', #define true or false
                'auto.offset.reset': 'latest' #define offset ['latest', 'earliest', 'none']
            }
        }

        res = self.request.post(self.base_url + self.path + 'consumers', headers=self.headers, json=payload)

        if res.status_code in [200, 201, 202, 204]:
            self.consumer_id = res.json()['consumerInstanceId']
            Log().logger('Consumer ID for this session: {}'.format(self.consumer_id))
        else:
            Log().logger('Unexpected error {}: {}'.format(res.status_code, res.text))

    def subscribe(self):
        if not self.consumer_id:
            self.create()

        payload = {'topics': TOPICS}

        res = self.request.post(self.base_url + self.path + 'consumers/{}/subscription'.format(self.consumer_id), headers=self.headers, json=payload)

        if res.status_code in [200, 201, 202, 204]:
            self.subscribed = True
            Log().logger('Successfully subscribed to topic {}'.format(str(TOPICS)))
        elif res.status_code in [404]:
            Log().logger('Consumer {} does not exist'.format(self.consumer_id))
        else:
            Log().logger('Unexpected error {}: {}'.format(res.status_code, res.text))

    def consume(self):
        res = self.request.get(self.base_url + self.path + 'consumers/{}/records'.format(self.consumer_id), headers=self.headers)

        if res.status_code in [200, 201, 202, 204]:
            try:
                if not res.json()['records']:
                    pass
                else:
                    for record in res.json()['records']:
                        payload = json.loads(base64.b64decode(record['message']['payload']))
                        Log().logger(payload)
                        self.send_syslog(json.dumps(payload, separators=(",", ":"), sort_keys=True))
            except Exception as e:
                Log().logger('Unexpected error during parsing: {}'.format(str(e)))
        elif res.status_code in [404]:
            Log().logger('Consumer {} does not exist'.format(self.consumer_id))
        else:
            Log().logger('Unexpected error {}: {}'.format(res.status_code, res.text))

    def delete(self):
        res = self.request.delete(self.base_url + self.path + 'consumers/{}'.format(self.consumer_id), headers=self.headers)

        if res.status_code in [200, 201, 202, 204]:
            self.consumer_id = None
            Log().logger('Successfully deleted consumer from MVISION EDR')
        elif res.status_code in [404]:
            self.consumer_id = None
            Log().logger('Consumer {} does not exist'.format(self.consumer_id))
        else:
            Log().logger('Unexpected error {}: {}'.format(res.status_code, res.text))

    def send_syslog(self, event):
        time = datetime.today().strftime('%b %d %H:%M:%S')
        msg = time + ' MVISION EDR[0]: ' + event

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (SYSLOG_SERVER, SYSLOG_PORT))
        sock.close()


class Log():
    def logger(self, msg):
        t = datetime.now()
        print(msg)
        with open('log.txt', 'a') as logfile:
            logfile.write('{}: {}\n'.format(t, msg))
            logfile.close()


if __name__ == '__main__':
    try:
        os.remove('log.txt')
    except:
        pass

    edr = MVISIONEDR()
    status = False

    edr.create()
    edr.subscribe()
    while mvision_edr_globals.interrupted is False:
        edr.consume()
        time.sleep(5)

    edr.delete()

    print('done')
