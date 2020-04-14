#!/usr/bin/env python3
# Written by mohlcyber v.0.1 (15.04.2020)

import sys
import socket
import requests
import json
import re
import smtplib

from datetime import datetime
from urllib.parse import urljoin
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

#Used for comments in Cases and Email
EDR_URL = 'https://ui.soc.eu-central-1.mcafee.com/monitoring/'


class Syslog():
    def __init__(self, kwargs):
        self.syslog = kwargs.get('syslog')
        self.port = kwargs.get('port')

    def run(self, event):
        try:
            event = json.dumps(event, separators=(",", ":"), sort_keys=True)
            time = datetime.today().strftime('%b %d %H:%M:%S')
            msg = time + ' MVISION EDR[0]: ' + event

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode(), (self.syslog, int(self.port)))
            sock.close()
            print('SUCCESS: Successfully send Syslog to {0}.'.format(str(self.syslog)))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


class TheHive():
    def __init__(self, kwargs):
        self.base_url = kwargs.get('url')
        self.port = kwargs.get('port')
        self.session = requests.Session()
        self.verify = False

        token = kwargs.get('token')
        self.headers = {'Authorization': 'Bearer {0}'.format(token),
                        'Content-Type': 'application/json'}
        self.artifacts = []

    def create_case(self, event):
        try:
            name = str(event['threat']['threatAttrs']['name'])
            edr_severity = str(event['threat']['severity'])
            if edr_severity == 's4' or edr_severity == 's5':
                severity = 3
            elif edr_severity == 's2' or edr_severity == 's3':
                severity = 2
            else:
                severity = 1

            self.artifacts.append(event['threat']['threatAttrs']['md5'])
            self.artifacts.append(event['threat']['threatAttrs']['sha1'])
            self.artifacts.append(event['threat']['threatAttrs']['sha256'])

            payload = {
                'title': 'MVISION EDR Threat Detection - {0}'.format(name),
                'description': 'This case has been created by MVISION EDR',
                'severity': severity,
                'tlp': 3,
                'tags': ['edr', 'threat']
            }
            res = self.session.post('{0}:{1}/api/case'.format(self.base_url, self.port),
                                    headers=self.headers, data=json.dumps(payload), verify=self.verify)

            if res.ok:
                caseId = res.json()['id']
                for artifact in self.artifacts:
                    self.add_observable(caseId, artifact)
            else:
                print('ERROR: HTTP {0} - {1}'.format(str(res.status_code), res.content))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def add_observable(self, caseId, artifact):
        try:
            payload = {
                'dataType': 'hash',
                'data': artifact,
                'ioc': True,
                'tlp': 3,
                'tags': ['edr', 'threat'],
                'message': 'MVISION EDR Threat Detection'
            }

            self.session.post('{0}:{1}/api/case/{2}/artifact'.format(self.base_url, self.port, str(caseId)),
                              headers=self.headers, data=json.dumps(payload), verify=self.verify)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def run(self, event):
        self.create_case(event)
        print('SUCCESS: Successfully created case in TheHive - {0}.'.format(str(self.base_url)))


class Email():
    def __init__(self, kwargs):
        self.smtp = kwargs.get('smtp')
        self.smtpport = kwargs.get('port')
        self.smtpuser = kwargs.get('user')
        self.smtppw = kwargs.get('pw')
        self.recipient = kwargs.get('recipient')

    def run(self, event):
        try:
            time = datetime.today().strftime('%d %B %Y')
            name = str(event['threat']['threatAttrs']['name'])
            title = 'MVISION EDR Threat Detection - {0}'.format(name)

            message = MIMEMultipart("alternative")
            message["Subject"] = title
            message["From"] = self.smtpuser
            message["To"] = self.recipient

            html = open('modules/email.html', 'r').read()
            html = re.sub(r'(##DATE##)', time, html)
            html = re.sub(r'(##TITLE##)', title, html)
            html = re.sub(r'(##NAME##)', name, html)
            html = re.sub(r'(##MD5##)', str(event['threat']['threatAttrs']['md5']), html)
            html = re.sub(r'(##SHA1##)', str(event['threat']['threatAttrs']['sha1']), html)
            html = re.sub(r'(##SHA256##)', str(event['threat']['threatAttrs']['sha256']), html)
            html = re.sub(r'(##USER##)', str(event['user']), html)
            html = re.sub(r'(##MAGUID##)', str(event['threat']['maGuid']), html)
            html = re.sub(r'(##THREATTYPE##)', str(event['threat']['threatType']), html)

            html = re.sub(r'(##LINK##)', EDR_URL, html)

            message.attach(MIMEText(html, "html"))

            with smtplib.SMTP(self.smtp, self.smtpport) as server:
                server.ehlo()
                server.starttls()
                server.login(self.smtpuser, self.smtppw)
                server.sendmail(self.smtpuser, self.recipient, message.as_string())
                server.quit()

            print('SUCCESS: Successfully sent Email to {0}.'.format(self.recipient))

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


class ServiceNow():
    def __init__(self, kwargs):
        self.url = kwargs.get('url')
        user = kwargs.get('user')
        pwd = kwargs.get('pw')
        self.creds = (user, pwd)

        self.snow_user = 'MVISION EDR'

        self.headers = {"Content-Type": "application/json", "Accept": "application/json"}
        self.session = requests.Session()

    def check_user(self):
        try:
            res = self.session.get(urljoin(self.url, '/api/now/table/sys_user?sysparm_query=GOTO123TEXTQUERY321%3DMcAfee%20EDR'),
                                   auth=self.creds, headers=self.headers)
            print(res.text)
            if res.json().get("result"):
                return True
            else:
                return False
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def create_user(self):
        try:
            new_user = {
                "name": self.snow_user,
                "user_name": self.snow_user,
                "first_name": "McAfee",
                "last_name": self.snow_user
            }

            res = self.session.post(urljoin(self.url, '/api/now/table/sys_user'), auth=self.creds,
                                    headers=self.headers, data=json.dumps(new_user))

            if not res.ok:
                print('ERROR: SNOW Something went wrong during the User creation: {} - {}'
                      .format(res.status_code, res.text))
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def create_incident(self, severity, short_desc, desc):
        try:
            payload = {
                "caller_id": self.snow_user,
                "category": "software",
                "contact_type": "Self-service",
                "state": "0",
                "impact": severity, #variable 3-High, 2-Medium, 1-Low
                "urgency": '2',#severity, #variable 3-High, 2-Medium, 1-Low
                #"assignment_group": "IT Securities",
                "assigned_to": self.snow_user,
                "short_description": short_desc, #Variable for MVISION EDR Text
                "description": desc #Hashes and URL for the investigation
            }

            res = self.session.post(urljoin(self.url, '/api/now/table/incident'), auth=self.creds, headers=self.headers, data=json.dumps(payload))
            if not res.ok:
                print('ERROR: SNOW Something went wrong to create an Incident in ServiceNow: {0} - {1}'.format(res.status_code, res.text))
            else:
                print('SUCCESS: Successfully created case in SNOW.')
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def run(self, event):
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

            desc = 'MD5: {0} | SHA1: {1} | SHA256: {2} | URL: {3}'.format(md5, sha1, sha256, EDR_URL)

            if self.check_user() is False:
                self.create_user()
            self.create_incident(severity, short_desc, desc)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: SNOW Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))
