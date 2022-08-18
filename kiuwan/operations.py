""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('kiuwan')

errors = {
    '401': 'Unauthorized, API key invalid',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}


class Kiuwan(object):
    def __init__(self, config, *args, **kwargs):
        self.username = config.get('username')
        self.password = config.get('password')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/'.format(url)
        else:
            self.url = url + '/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {
                'Accept': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, json=data, params=params, auth=(self.username, self.password),
                                        headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return response
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def get_progress_summary_for_action_plan(config, params):
    kw = Kiuwan(config)
    endpoint = 'actionPlan'
    try:
        payload = {
            'application': params.get('app_name'),
            'name': params.get('action_name'),
            'creation': params.get('creation_date')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_analysis_list(config, params):
    kw = Kiuwan(config)
    endpoint = 'analysis/list'
    try:
        payload = {
            'applicationName': params.get('app_name'),
            'auditStatus': params.get('audit_status'),
            'count': params.get('count'),
            'deliveries': params.get('deliveries'),
            'initDate': params.get('start_date'),
            'endDate': params.get('end_date'),
            'page': params.get('page'),
            'status': params.get('status')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def delete_analysis(config, params):
    kw = Kiuwan(config)
    endpoint = 'analysis'
    try:
        payload = {
            'analysisCode': params.get('analysis_code')
        }
        response = kw.make_rest_call(endpoint, 'DELETE', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def create_mutes_for_rule_or_file(config, params):
    kw = Kiuwan(config)
    endpoint = 'applications/defects/mute'
    try:
        payload = {
            'application': params.get('app_name'),
            'comment': params.get('comment'),
            'fileName': params.get('file_name'),
            'filePattern': params.get('file_pattern'),
            'rule': params.get('rule'),
            'why': params.get('reason')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'POST', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = get_analysis_list(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_progress_summary_for_action_plan': get_progress_summary_for_action_plan,
    'get_analysis_list': get_analysis_list,
    'delete_analysis': delete_analysis,
    'create_mutes_for_rule_or_file': create_mutes_for_rule_or_file
}
