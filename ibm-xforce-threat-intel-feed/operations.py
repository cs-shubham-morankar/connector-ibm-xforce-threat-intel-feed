"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import requests, os, json
import uuid
from connectors.cyops_utilities.builtins import create_file_from_string
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.files import get_ingestion_base_dir
from datetime import datetime

try:
    from integrations.crudhub import trigger_ingest_playbook
except:
    # ignore. lower FSR version
    pass

logger = get_logger('ibm-xforce-threat-intel-feed')


class TaxiiClient(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.api_key = config.get('api_key')
        self.api_password = config.get('api_password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request_taxii(self, endpoint=None, method='GET', data=None, params=None, files=None, headers=None):
        try:
            url = self.server_url + endpoint
            default_header = {'Content-Type': 'application/json'}
            headers = {**default_header, **headers} if headers is not None and headers != '' else default_header
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl, auth=(self.api_key, self.api_password))
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def get_params(params):
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_output_schema(config, params, **kwargs):
    mode = params.get('output_mode')
    if mode == 'Save to File':
        return ({
            "md5": "",
            "sha1": "",
            "sha256": "",
            "filename": "",
            "content_length": "",
            "content_type": ""
        })
    else:
        return ({
            "spec_version": "",
            "type": "",
            "objects": [
                {
                    "id": "",
                    "type": "",
                    "created": "",
                    "published": "",
                    "modified": "",
                    "labels": [
                    ],
                    "name": "",
                    "description": "",
                    "pattern": "",
                    "valid_from": "",
                    "object_refs": [],
                    "x_com_ibm_short_description": "",
                    "x_com_ibm_source_pdf": "",
                    "x_com_ibm_source": "",
                    "x_com_ibm_tags": [],
                    "x_com_ibm_iris_tags": []
                }
            ]
        })


def get_api_root_information(config, params, **kwargs):
    taxii = TaxiiClient(config)
    params = get_params(params)
    api_root = taxii.make_request_taxii(endpoint='taxii2/', params=params,
                                        headers={'Accept': 'application/vnd.oasis.taxii+json'})
    try:
        resp = api_root['api_roots'][0]
        return resp
    except:
        return 'taxii2/'


def get_collections(config, params, **kwargs):
    taxii = TaxiiClient(config)
    api_root = get_api_root_information(config, params, **kwargs)
    params = get_params(params)
    if params:
        response = taxii.make_request_taxii(endpoint=api_root + 'collections/' + str(params['collectionID']),
                                            headers={'Accept': 'application/vnd.oasis.taxii+json'})
    else:
        response = taxii.make_request_taxii(endpoint=api_root + 'collections/',
                                            headers={'Accept': 'application/vnd.oasis.taxii+json'})
    if response.get('collections'):
        return response
    else:
        return {'collections': [response]}


def get_objects_by_collection_id(config, params, **kwargs):
    taxii = TaxiiClient(config)
    api_root = get_api_root_information(config, params, **kwargs)
    params = get_params(params)
    wanted_keys = set(['added_after', 'added_before'])
    mode = params.get('output_mode')
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    try:
        response = taxii.make_request_taxii(
            endpoint=api_root + 'collections/' + str(params['collectionID']) + '/objects',
            params=query_params, headers={'Accept': 'application/vnd.oasis.stix+json'})
        response = response.get("objects", [])
        filtered_indicators = [indicator for indicator in response if indicator["type"] == "indicator"]
    except Exception as e:
        if mode == 'Create as Feed Records in FortiSOAR':
            return 'No records ingested'
        raise ConnectorError(str(e))
    if mode == 'Create as Feed Records in FortiSOAR':
        create_pb_id = params.get("create_pb_id")
        trigger_ingest_playbook(filtered_indicators, create_pb_id, parent_env=kwargs.get('env', {}), batch_size=1000,
                                dedup_field="pattern")
        return 'Successfully triggered playbooks to create feed records'
    seen = set()
    deduped_indicators = [x for x in filtered_indicators if [x["pattern"] not in seen, seen.add(x["pattern"])][0]]
    if mode == 'Save to File':
        return create_file_from_string(contents=deduped_indicators, filename=params.get('filename'))
    else:
        return deduped_indicators


def get_manifest_by_collection_id(config, params, **kwargs):
    taxii = TaxiiClient(config)
    api_root = get_api_root_information(config, params, **kwargs)
    params = get_params(params)
    wanted_keys = set(['added_after', 'added_before'])
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    return taxii.make_request_taxii(endpoint=api_root + 'collections/' + str(params['collectionID']) + '/manifest',
                                    params=query_params, headers={'Accept': 'application/vnd.oasis.taxii+json'})


def get_objects_by_object_id(config, params, **kwargs):
    taxii = TaxiiClient(config)
    api_root = get_api_root_information(config, params, **kwargs)
    params = get_params(params)
    return taxii.make_request_taxii(headers={'Accept': 'application/vnd.oasis.stix+json'},
                                    endpoint=api_root + 'collections/' + str(params['collectionID']) + '/objects/' +
                                             params[
                                                 'objectID'])


def download_indicators(config, params, **kwargs):
    collection_ids = []
    config_id = config.get('config_id')
    api_root = get_api_root_information(config, params={}, **kwargs)
    taxii = TaxiiClient(config)
    get_collections_ids = get_collections(config, params={}, **kwargs)

    # Extract IDs if the collections list is not empty
    if get_collections_ids.get("collections"):
        collection_ids = [collection.get("id") for collection in get_collections_ids["collections"] if
                          "id" in collection]

    wanted_keys = set(['added_after'])
    results = []
    query_params = {k: params[k] for k in params.keys() & wanted_keys}
    if collection_ids:
        for collection_id in collection_ids:
            response = taxii.make_request_taxii(
                endpoint=f"{api_root}collections/{collection_id}/objects",
                params=query_params, headers={'Accept': 'application/vnd.oasis.stix+json'})
            response = response.get("objects", [])
            filtered_indicators = [indicator for indicator in response if indicator.get("type") == "indicator"]
            seen = set()
            deduped_indicators = [x for x in filtered_indicators if
                                  [x["pattern"] not in seen, seen.add(x["pattern"])][0]]
            results.append({"indicators": deduped_indicators})
    else:
        results.append({"indicators": []})
    base_indicator_dir = get_ingestion_base_dir(**kwargs)
    try:
        os.makedirs(base_indicator_dir, exist_ok=True)
    except Exception as e:
        base_indicator_dir = '/tmp/'
        logger.warn("Not able to create dir for downloading indicators")

    config_dir = base_indicator_dir + config_id + '/'
    try:
        os.makedirs(config_dir, exist_ok=True)
    except Exception as e:
        pass
    file_name = str(uuid.uuid4()) + '.json'
    file_path = os.path.join(config_dir, file_name)
    with open(file_path, "w") as json_file:
        json.dump(results, json_file, indent=2)

    return {"files": [file_path.replace(base_indicator_dir, '')], "last_pull_datetime": datetime.now()}


def _check_health(config):
    try:
        params = {}
        res = get_api_root_information(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_api_root_information': get_api_root_information,
    'get_collections': get_collections,
    'get_objects_by_collection_id': get_objects_by_collection_id,
    'get_objects_by_object_id': get_objects_by_object_id,
    'get_manifest_by_collection_id': get_manifest_by_collection_id,
    'get_output_schema': get_output_schema,
    'download_indicators': download_indicators
}
