#!/usr/bin/env python3
# Written by mohlcyber v.1.7 (13.06.2022)
# Script to retrieve all threats from the monitoring dashboard

import sys
import requests
import time
import logging
import json
import os
import pytz

from datetime import datetime, timedelta
from dateutil import tz
from logging.handlers import SysLogHandler
from dotenv import load_dotenv

load_dotenv(verbose=True)


class EDR():
    def __init__(self):
        self.iam_url = 'iam.mcafee-cloud.com/iam/v1.1'
        if edr_region == 'EU':
            self.base_url = 'soc.eu-central-1.trellix.com'
        elif edr_region == 'US-W':
            self.base_url = 'soc.trellix.com'
        elif edr_region == 'US-E':
            self.base_url = 'soc.us-east-1.trellix.com'
        elif edr_region == 'SY':
            self.base_url = 'soc.ap-southeast-2.trellix.com'
        elif edr_region == 'GOV':
            self.base_url = 'soc.mcafee-gov.com'

        self.session = requests.Session()

        if valid == 'False':
            self.session.verify = False
        else:
            self.session.verify = True

        if proxy is not None:
            self.session.proxies['https'] = proxy

        creds = (edr_client_id, edr_client_secret)

        self.pattern = '%Y-%m-%dT%H:%M:%S.%f'
        self.cache_fname = '{0}/cache.log'.format(cache_dir)
        if os.path.isfile(self.cache_fname):
            cache = open(self.cache_fname, 'r')
            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')
            last_detection_utc = last_detection.replace(tzinfo=pytz.UTC)
            next_pull = last_detection_utc.astimezone(tz.tzlocal()) + timedelta(seconds=1)

            logger.debug('Cache exists. Last detection date UTC: {0}'.format(last_detection))
            logger.debug('Pulling newest threats from: {0}'.format(next_pull))
            cache.close()
        else:
            logger.debug('Cache does not exists. Pulling data from last {0} days.'.format(initial_pull))
            next_pull = datetime.now() - timedelta(days=int(initial_pull))

        self.epoch_pull = str(datetime.timestamp(next_pull)*1000)[:13]
        logger.debug('New pulling date {0} - epoch {1}'.format(next_pull, self.epoch_pull))

        self.auth(creds)
        self.limit = 10000

    def auth(self, creds):
        try:
            payload = {
                'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
                'grant_type': 'client_credentials',
                'audience': 'mcafee'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            if res.ok:
                token = res.json()['access_token']
                self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
                logger.debug('AUTHENTICATION: Successfully authenticated.')
            else:
                logger.error('Error in retrieving edr.auth(). Request url: {}'.format(res.url))
                logger.error('Error in retrieving edr.auth(). Request headers: {}'.format(res.request.headers))
                logger.error('Error in retrieving edr.auth(). Request body: {}'.format(res.request.body))
                raise Exception('Error in retrieving edr.auth(). Error: {0} - {1}'.format(str(res.status_code), res.text))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_threats(self):
        try:
            tthreat = 0
            tdetect = 0
            skip = 0
            tnextflag = True

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities
            filter['scoreRange'] = [30]

            while(tnextflag):
                res = self.session.get(
                    'https://api.{0}/ft/api/v2/ft/threats?sort=-lastDetected&filter={1}&from={2}&limit={3}&skip={4}'
                        .format(self.base_url, json.dumps(filter), self.epoch_pull, self.limit, skip))

                if res.ok:
                    res = res.json()

                    if int(res['skipped']) + int(res['items']) == int(res['total']):
                        tnextflag = False
                    else:
                        skip = int(res['skipped']) + int(res['items'])

                    if len(res['threats']) > 0:
                        if os.path.isfile(self.cache_fname):
                            cache = open(self.cache_fname, 'r')
                            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')
                            cache.close()
                            if last_detection < (datetime.strptime(res['threats'][0]['lastDetected'], '%Y-%m-%dT%H:%M:%SZ')):
                                logger.debug('More recent detection timestamp detected. Updating cache.log.')
                                cache = open(self.cache_fname, 'w')
                                cache.write(res['threats'][0]['lastDetected'])
                                cache.close()
                            else:
                                logger.debug('More recent detection timestamp in cache.log already saved.')
                        else:
                            cache = open(self.cache_fname, 'w')
                            cache.write(res['threats'][0]['lastDetected'])
                            cache.close()

                        for threat in res['threats']:
                            affhosts = self.get_affected_hosts(threat['id'])
                            ddetect_count = 0
                            for host in affhosts:
                                detections = self.get_detections(threat['id'], host['id'])

                                for detection in detections:
                                    threat['detection'] = detection

                                    traceid = detection['traceId']
                                    maguid = detection['host']['maGuid']
                                    sha256 = detection['sha256']

                                    threat['url'] = 'https://ui.{0}/monitoring/#/workspace/72,TOTAL_THREATS,{1}?traceId={2}&maGuid={3}&sha256={4}' \
                                        .format(self.base_url, threat['id'], traceid, maguid, sha256)

                                    logger.debug(json.dumps(threat))
                                    logger.info('Retrieved new MVISION EDR Threat Detection. {0}'.format(threat['name']))

                                    if syslog_ip and syslog_port:
                                        syslog.info(json.dumps(threat, sort_keys=True))
                                        logger.info('Successfully send data to Syslog IP {}'.format(syslog_ip))

                                    if threat_log == 'True':
                                        if os.path.exists(threat_dir) is False:
                                            os.mkdir(threat_dir)

                                        time_detect = detection['firstDetected']
                                        ptime_detect = datetime.strptime(time_detect, '%Y-%m-%dT%H:%M:%SZ')
                                        filename = '{}-{}.log'.format(ptime_detect.strftime('%Y%m%d%H%M%S'), threat['name'])
                                        file = open('{}/{}'.format(threat_dir, filename), 'w')
                                        file.write(json.dumps(threat))
                                        file.close()

                                    tdetect += 1
                                    ddetect_count += 1

                            logger.debug('For threat {0} identified {1} new detections.'.format(threat['name'], ddetect_count))
                            tthreat += 1

                    else:
                        logger.debug('No new threats identified. Exiting. {0}'.format(res))

                else:
                    logger.error('Error in retrieving edr.get_threats(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_threats(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_threats(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_threats(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            logger.debug('Pulled total {0} Threats and {1} Detections.'.format(tthreat, tdetect))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_affected_hosts(self, threatId):
        try:
            skip = 0
            anextflag = True
            affhosts = []

            while(anextflag):

                res = self.session.get(
                    'https://api.{0}/ft/api/v2/ft/threats/{1}/affectedhosts?sort=-rank&from={2}&limit={3}&skip={4}'
                        .format(self.base_url, threatId, self.epoch_pull, self.limit, skip))

                if res.ok:
                    res = res.json()
                    if int(res['skipped']) + int(res['items']) == int(res['total']):
                        anextflag = False
                    else:
                        skip = int(res['skipped']) + int(res['items'])

                    if len(affhosts) == 0:
                        affhosts = res['affectedHosts']
                    else:
                        for affhost in res['affectedHosts']:
                            affhosts.append(affhost)

                else:
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_affectedHosts(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            return affhosts

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_detections(self, threatId, affhost):
        try:
            skip = 0
            dnextflag = True
            detections = []

            while(dnextflag):
                filter = {
                    'affectedHostId': affhost
                }

                res = self.session.get(
                    'https://api.{0}/ft/api/v2/ft/threats/{1}/detections?sort=-rank&from={2}&filter={3}&limit={4}&skip={5}'
                        .format(self.base_url, threatId, self.epoch_pull, json.dumps(filter), self.limit, skip))

                if res.ok:
                    res = res.json()
                    if int(res['skipped']) + int(res['items']) == int(res['total']):
                        dnextflag = False
                    else:
                        skip = int(res['skipped']) + int(res['items'])

                    if len(detections) == 0:
                        detections = res['detections']
                    else:
                        for detection in res['detections']:
                            detections.append(detection)
                else:
                    logger.error('Error in retrieving edr.get_detections(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_detections(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_detections(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_detections(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            return detections

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise


if __name__ == '__main__':
    edr_region = os.getenv('EDR_REGION')
    edr_client_id = os.getenv('EDR_CLIENT_ID')
    edr_client_secret = os.getenv('EDR_CLIENT_SECRET')

    interval = os.getenv('INTERVAL')
    initial_pull = os.getenv('INITIAL_PULL')

    syslog_ip = os.getenv('SYSLOG_IP')
    syslog_port = os.getenv('SYSLOG_PORT')

    proxy = os.getenv('PROXY')
    valid = os.getenv('VALID')

    cache_dir = os.getenv('CACHE_DIR')

    log_level = os.getenv('LOG_LEVEL')
    log_dir = os.getenv('LOG_DIR')

    threat_log = os.getenv('THREAT_LOG')
    threat_dir = os.getenv('THREAT_DIR')

    # setup logging
    logger = logging.getLogger('mvedr_logger')
    logger.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")

    # setup the console logger
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # setup the file logger
    if os.path.exists(log_dir) is False:
        os.mkdir(log_dir)

    file_handler = logging.handlers.RotatingFileHandler('{0}/mvedr_logger.log'.format(log_dir), maxBytes=25000000,
                                                        backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if syslog_ip and syslog_port:
        syslog = logging.getLogger('syslog')
        syslog.setLevel(log_level)
        syslog.addHandler(SysLogHandler(address=(syslog_ip, int(syslog_port))))

    while True:
        try:
            edr = EDR()
            edr.get_threats()
            edr.session.close()
            time.sleep(int(interval))
        except Exception:
            time.sleep(60)
