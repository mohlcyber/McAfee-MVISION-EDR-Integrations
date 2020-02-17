#v.0.1 written by mohlcyber
#This example uses the ServiceNow API to create Incidents for MVISION EDR

import json
import socket
import time
import requests

from datetime import datetime, timedelta
from dxlstreamingclient.channel import Channel, ChannelAuth

#MVISION EDR Config
EDR_USER = 'test@test.com'
EDR_PW = 'password'
EDR_TOPICS = ['threatEvents']

#ServiceNow Config
SNOW_URL = 'https://xxxx.service-now.com/api/now/table/'
SNOW_USER = 'user'
SNOW_PW = 'password'
SNOW_SUBMITTER = 'MVISION EDR'

#Syslog Server Config
SYSLOG_SERVER = '1.1.1.1'
SYSLOG_PORT = 514

class EDR():
    def __init__(self):
        self.url = 'https://api.soc.mcafee.com/'
        self.user = EDR_USER
        self.pw = EDR_PW
        self.topics = EDR_TOPICS

        self.creds = (self.user, self.pw)
        self.channel_auth = ChannelAuth(self.url, self.user, self.pw, verify_cert_bundle='')

    def activity_feed(self):
        try:
            with Channel(self.url, auth=self.channel_auth, consumer_group='mvisionedr_events', verify_cert_bundle='') as channel:

                def process_callback(payloads):

                    if not payloads == []:
                        for payload in payloads:
                            print(json.dumps(payload))
                            Log().syslogger(json.dumps(payload, separators=(",", ":"), sort_keys=True))

                            if payload['entity'] == 'threat':
                                self.send_snow(payload)

                    return True

                channel.run(process_callback, wait_between_queries=5, topics=self.topics)

        except Exception as e:
            print("ERROR: Unexpected error: {}".format(e))

    def _auth(self):
        r = requests.get(self.url + 'identity/v1/login', auth=self.creds)
        res = r.json()

        if r.status_code == 200:
            token = res['AuthorizationToken']
            self.headers = {'Authorization': 'Bearer {}'.format(token)}
            Log().logger('SUCCESS: Successfully authenticated.')
        else:
            Log().logger('ERROR: Something went wrong during the authentication')

    def calc_url(self, sha256):
        self._auth()
        url = 'https://ui.soc.mcafee.com/monitoring/#/workspace/72,TOTAL_THREATS'

        today = datetime.now()
        epoch_today = int(time.mktime(today.timetuple()))

        before = today - timedelta(3)
        epoch_before = int(time.mktime(before.timetuple()))

        try:
            res = requests.get(self.url + 'ft/api/v2/ft/threats?sort=-rank&limit=100&from={0}027&to={1}027'.format(epoch_before, epoch_today), headers=self.headers)

            for threat in res.json()['threats']:
                check = threat['hashes']['sha256']
                if check == sha256:
                    id = threat['id']
                    url = 'https://ui.soc.mcafee.com/monitoring/#/workspace/72,TOTAL_THREATS,{}'.format(id)
                    break
        except:
            pass

        return url

    def send_snow(self, event):
        try:
            if event['threat']['severity'] == 's1':
                severity = '3'
            elif event['threat']['severity'] == 's3':
                severity = '2'
            elif event['threat']['severity'] == 's5':
                severity = '1'
            else:
                severity = '3'

            short_desc = event['threat']['eventType'] + ' ' + event['threat']['threatAttrs']['name']
            md5 = event['threat']['threatAttrs']['md5']
            sha1 = event['threat']['threatAttrs']['sha1']
            sha256 = event['threat']['threatAttrs']['sha256']
            url = self.calc_url(sha256)

            desc = 'MD5: {0} | SHA1: {1} | SHA256: {2} | URL: {3}'.format(md5, sha1, sha256, url)

            snow = ServiceNow()
            if snow.check_user() == False:
                snow.create_user()
            snow.create_incident(severity, short_desc, desc)
        except Exception as e:
            Log().logger('ERROR: Something went wrong during the incident creation process. {}'.format(e))
            pass


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


class ServiceNow():

    def __init__(self):
        self.url = SNOW_URL
        self.user = SNOW_USER
        self.pwd = SNOW_PW
        self.creds = (self.user, self.pwd)

        self.snow_user = SNOW_SUBMITTER

        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}

    def check_user(self):
        res = requests.get(self.url + 'sys_user?sysparm_query=GOTO123TEXTQUERY321%3DMcAfee%20EDR',auth=self.creds, headers=self.headers)
        if not res.json().get("result"):
            return False
        else:
            print('SUCCESS: User got generated already')
            return True

    def create_user(self):
        new_user = {
            "name": self.snow_user,
            "user_name": self.snow_user,
            "first_name": "McAfee",
            "last_name": self.snow_user
        }

        res = requests.post(self.url + 'sys_user', auth=self.creds, headers=self.headers, data=new_user)

        if res.status_code == 201:
            print('SUCCESS: User {0} got generated successfully with the ID: {1}'.format('MVISION EDR', res.json()['result']['sys_id']))
        else:
            print('ERROR: Something went wrong during the User creation: {} - {}'.format(res.status_code, res.text))

    def create_incident(self, severity, short_desc, desc):
        payload = {
            "caller_id": self.snow_user,
            "category": "software",
            "contact_type": "Self-service",
            "state": "0",
            "impact": severity, #variable 3-High, 2-Medium, 1-Low
            "urgency": '2',#severity, #variable 3-High, 2-Medium, 1-Low
            "assignment_group": "IT Securities",
            "assigned_to": self.snow_user,
            "short_description": short_desc, #Variable for MVISION EDR Text
            "description": desc #Hashes and URL for the investigation
        }

        res = requests.post(self.url + 'incident', auth=self.creds, headers=self.headers, data=json.dumps(payload))
        if res.status_code == 201:
            print('SUCCESS: Successfully created Incident with the ID: {}'.format(res.json()['result']['sys_id']))
        else:
            print('ERROR: Something went wrong to create an Incident in ServiceNow: {} - {}'.format(res.status_code, res.text))


if __name__ == "__main__":
    edr = EDR()
    edr.activity_feed()
