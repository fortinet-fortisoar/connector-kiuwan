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

Vuln_Type = {
    "Permissions": "Permissions",
    "Privileges and Access Controls": "privileges and access controls",
    "Injection": "Injection",
    "Error Handling and Fault Isolation": "Error handling and fault isolation",
    "Other": "Other",
    "Encryption and Randomness": "Encryption and randomness",
    "Misconfiguration": "Misconfiguration",
    "Design Error": "Design error",
    "Initialization and Shutdown": "Initialization and shutdown",
    "Control Flow Management": "Control flow management",
    "File Handling": "File handling",
    "Number Handling": "Number handling",
    "System Element Isolation": "System element isolation",
    "Buffer Handling": "Buffer handling",
    "Information Leaks": "Information leaks",
    "Pointer and Reference Handling": "Pointer and reference handling"
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
            response = requests.request(method, url, data=data, params=params, auth=(self.username, self.password),
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


def get_defects_list_for_action_plan(config, params):
    kw = Kiuwan(config)
    endpoint = 'actionPlan/defects/all'
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


def get_pending_defects_for_action_plan(config, params):
    kw = Kiuwan(config)
    endpoint = 'actionPlan/defects/pending'
    orderBy = params.get('orderBy')
    if orderBy:
        orderBy = orderBy.lower()
    try:
        payload = {
            'application': params.get('app_name'),
            'name': params.get('action_name'),
            'creation': params.get('creation_date'),
            'analysisLabel': params.get('analysisLabel'),
            'asc': params.get('sort_by'),
            'characteristics': params.get('characteristics'),
            'fileContains': params.get('fileContains'),
            'languages': params.get('languages'),
            'limit': params.get('limit'),
            'orderBy': orderBy,
            'priorities': params.get('priorities')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_removed_defects_for_action_plan(config, params):
    kw = Kiuwan(config)
    endpoint = 'actionPlan/defects/removed'
    try:
        payload = {
            'application': params.get('app_name'),
            'name': params.get('action_name'),
            'creation': params.get('creation_date'),
            'analysisLabel': params.get('analysisLabel')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_available_action_plans(config, params):
    kw = Kiuwan(config)
    endpoint = 'actionPlans'
    try:
        payload = {
            'application': params.get('app_name')
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


def get_analysis_codes_list(config, params):
    kw = Kiuwan(config)
    endpoint = 'applications/analyses'
    try:
        payload = {
            'application': params.get('app_name'),
            'filterPurgedAnalyses': params.get('filterPurgedAnalyses'),
            'count': params.get('count'),
            'success': params.get('success')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_latest_analysis_files_list(config, params):
    kw = Kiuwan(config)
    endpoint = 'applications/files'
    try:
        payload = {
            'application': params.get('app_name')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_last_analysis(config, params):
    kw = Kiuwan(config)
    endpoint = 'applications/last_analysis'
    try:
        payload = {
            'application': params.get('app_name')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_application_analysis(config, params):
    kw = Kiuwan(config)
    endpoint = 'apps/analysis/{0}'.format(params.get('code'))
    try:
        response = kw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_analysis_defects_list(config, params):
    kw = Kiuwan(config)
    endpoint = 'apps/analysis/{0}/defects'.format(params.get('code'))
    orderBy = params.get('orderBy')
    if orderBy:
        orderBy = orderBy.lower()
    try:
        payload = {
            'muted': params.get('muted'),
            'asc': params.get('sort_by'),
            'characteristics': params.get('characteristics'),
            'fileContains': params.get('fileContains'),
            'languages': params.get('languages'),
            'count': params.get('count'),
            'orderBy': orderBy,
            'priorities': params.get('priorities'),
            'page': params.get('page')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_comparison_defects(config, params):
    kw = Kiuwan(config)
    endpoint = 'apps/analysis/{0}/defects/compare/{1}'.format(params.get('code'), params.get('prev_code'))
    try:
        response = kw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_new_removed_defects_list(config, params):
    kw = Kiuwan(config)
    defect_type = params.get('defect_type').lower()
    endpoint = 'apps/analysis/{0}/defects/compare/{1}/{2}'.format(params.get('code'), params.get('prev_code'),
                                                                  defect_type)
    try:
        response = kw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_files_defects_details(config, params):
    kw = Kiuwan(config)
    endpoint = 'apps/analysis/{0}/files'.format(params.get('code'))
    try:
        response = kw.make_rest_call(endpoint, 'GET')
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


def create_suppresion_rule(config, params):
    kw = Kiuwan(config)
    endpoint = 'defect/{0}/mute'.format(params.get('defect_id'))
    try:
        payload = {
            'comment': params.get('comment'),
            'muteBy': params.get('muteBy'),
            'why': params.get('reason')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'POST', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_defect_notes(config, params):
    kw = Kiuwan(config)
    endpoint = 'defect/{0}/notes'.format(params.get('defect_id'))
    try:
        response = kw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_violated_rules(config, params):
    kw = Kiuwan(config)
    endpoint = 'violatedrules'
    vuln_type = params.get('vuln_type')
    if vuln_type:
        vuln_type = Vuln_Type.get(vuln_type)
    try:
        payload = {
            'analysisCode': params.get('analysisCode'),
            'application': params.get('app_name'),
            'characteristic': params.get('characteristic'),
            'language': params.get('language'),
            'onlyCodeSecurity': params.get('onlyCodeSecurity'),
            'priority': params.get('priority'),
            'tag': params.get('tag'),
            'vulnerabilityType': vuln_type,
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_violated_rule_files(config, params):
    kw = Kiuwan(config)
    endpoint = 'violatedrules/files'
    try:
        payload = {
            'analysisCode': params.get('analysisCode'),
            'application': params.get('app_name'),
            'ruleCode': params.get('ruleCode')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_file_defects(config, params):
    kw = Kiuwan(config)
    endpoint = 'violatedrules/files/defects'
    try:
        payload = {
            'analysisCode': params.get('analysisCode'),
            'application': params.get('app_name'),
            'file': params.get('file_name'),
            'ruleCode': params.get('ruleCode')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def update_defect_status(config, params):
    kw = Kiuwan(config)
    endpoint = 'defect/{0}/status'.format(params.get('defect_id'))
    try:
        payload = {
            'note': params.get('note'),
            'status': params.get('status')
        }
        payload = check_payload(payload)
        response = kw.make_rest_call(endpoint, 'GET', params=payload)
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
    'get_defects_list_for_action_plan': get_defects_list_for_action_plan,
    'get_pending_defects_for_action_plan': get_pending_defects_for_action_plan,
    'get_removed_defects_for_action_plan': get_removed_defects_for_action_plan,
    'get_available_action_plans': get_available_action_plans,
    'get_analysis_list': get_analysis_list,
    'get_analysis_codes_list': get_analysis_codes_list,
    'get_latest_analysis_files_list': get_latest_analysis_files_list,
    'get_last_analysis': get_last_analysis,
    'get_application_analysis': get_application_analysis,
    'get_analysis_defects_list': get_analysis_defects_list,
    'get_comparison_defects': get_comparison_defects,
    'get_new_removed_defects_list': get_new_removed_defects_list,
    'get_files_defects_details': get_files_defects_details,
    'delete_analysis': delete_analysis,
    'create_mutes_for_rule_or_file': create_mutes_for_rule_or_file,
    'create_suppresion_rule': create_suppresion_rule,
    'get_defect_notes': get_defect_notes,
    'get_violated_rules': get_violated_rules,
    'get_violated_rule_files': get_violated_rule_files,
    'get_file_defects': get_file_defects,
    'update_defect_status': update_defect_status
}
