""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from connectors.core.connector import get_logger, ConnectorError
from .oauth_token_handler import SailPointOAuth

logger = get_logger('sailpoint-identitynow')


class SailPointIdentityNow(object):
    def __init__(self, config):
        self.server_url = config.get('server_url', '').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self._server_url = 'https://' + self.server_url
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')
        self.connector_info = config.pop('connector_info', '')
        self.sp_auth = SailPointOAuth(config)
        self.token = self.sp_auth.validate_token(config, self.connector_info)
        self.headers = {'Content-Type': 'application/json', 'Authorization': '{}'.format(self.token)}


def get_accounts(config, params):
    query_string = {k: v for k, v in params.items() if v is not None and v != ''}
    sail_point = SailPointIdentityNow(config)
    return sail_point.sp_auth.make_rest_call('/v3/accounts', params=query_string, headers=sail_point.headers)


def get_account_details(config, params):
    account_id = params.get('id')
    endpoint = f'/v3/accounts/{account_id}'
    sail_point = SailPointIdentityNow(config)
    return sail_point.sp_auth.make_rest_call(endpoint, headers=sail_point.headers)


def get_account_activities(config, params):
    sail_point = SailPointIdentityNow(config)
    account_type = params.pop('account_type', '')
    if account_type:
        params.update({'filters': ''.join(('type eq "', account_type, '"'))})
    params['sorters'] = params.get('sorters', '').lower()
    query_string = {k: v for k, v in params.items() if v is not None and v != ''}
    return sail_point.sp_auth.make_rest_call('/v3/account-activities', params=query_string,
                                             headers=sail_point.headers)


def get_account_activity(config, params):
    sail_point = SailPointIdentityNow(config)
    activity_id = params.get('id')
    endpoint = f'/v3/account-activities/{activity_id}'
    return sail_point.sp_auth.make_rest_call(endpoint, headers=sail_point.headers)


def get_password_info(config, params):
    sail_point = SailPointIdentityNow(config)
    request_body = {k: v for k, v in params.items() if v is not None and v != ''}
    payload = json.dumps(request_body)
    sail_point.headers.update({'Accept': 'application/json'})
    return sail_point.sp_auth.make_rest_call('/v3/query-password-info', payload=payload,
                                             headers=sail_point.headers, method='POST')


def convert_password_rsa_encrypted_format(message, public_key):
    pub_key = RSA.importKey(public_key)
    cipher = Cipher_PKCS1_v1_5.new(pub_key)
    cipher_text = cipher.encrypt(message.encode())
    return base64.b64encode(cipher_text).decode()


def reset_password(config, params):
    user_name = params.pop('userName', '')
    source_name = params.pop('sourceName', '')
    password = params.pop('password', '')
    _params = {'userName': user_name, 'sourceName': source_name}
    password_info = get_password_info(config, _params)
    identity_id = password_info.get('identityId')
    public_key_id = password_info.get('publicKeyId')
    source_id = password_info.get('sourceId')
    public_key = password_info.get('publicKey')
    if (identity_id == params.get('identityId')) and (public_key_id == params.get(
            'publicKeyId')) and (source_id == params.get('sourceId')):
        request_body = {k: v for k, v in params.items() if v is not None and v != ''}
        rsa_encrypted_password = convert_password_rsa_encrypted_format(password, public_key)
        params['encryptedPassword'] = rsa_encrypted_password
        payload = json.dumps(request_body)
        sail_point = SailPointIdentityNow(config)
        sail_point.headers.update({'Accept': 'application/json'})
        return sail_point.sp_auth.make_rest_call('/v3/set-password', payload=payload, headers=sail_point.headers,
                                                 method='POST')
    else:
        return {'status': 'success', 'message': 'Specified user not found'}


def enable_account(config, params):
    sail_point = SailPointIdentityNow(config)
    account_id = params.pop('id', '')
    endpoint = f'/v3/accounts/{account_id}/enable'
    sail_point.headers.update({'Accept': 'application/json'})
    request_body = {k: v for k, v in params.items() if v is not None and v != ''}
    payload = json.dumps(request_body)
    return sail_point.sp_auth.make_rest_call(endpoint, payload=payload, headers=sail_point.headers, method='POST')


def disable_account(config, params):
    sail_point = SailPointIdentityNow(config)
    account_id = params.pop('id', '')
    endpoint = f'/v3/accounts/{account_id}/disable'
    sail_point.headers.update({'Accept': 'application/json'})
    request_body = {k: v for k, v in params.items() if v is not None and v != ''}
    payload = json.dumps(request_body)
    return sail_point.sp_auth.make_rest_call(endpoint, payload=payload, headers=sail_point.headers, method='POST')


def unlock_account(config, params):
    sail_point = SailPointIdentityNow(config)
    account_id = params.pop('id', '')
    endpoint = f'/v3/accounts/{account_id}/unlock'
    request_body = {k: v for k, v in params.items() if v is not None and v != ''}
    payload = json.dumps(request_body)
    return sail_point.sp_auth.make_rest_call(endpoint, payload=payload, headers=sail_point.headers, method='POST')


def access_request(config, params, request_type):
    sail_point = SailPointIdentityNow(config)
    request_for = params.get('requestedFor')
    requested_items = params.get('requestedItems')
    if not isinstance(requested_items, list):
        requested_items = [requested_items]
    if request_for and isinstance(request_for, str):
        request_for = request_for.split(',')
    payload = {
        'requestedFor': request_for,
        'requestType': request_type,
        'requestedItems': requested_items
    }
    client_meta_data = params.get('clientMetadata')
    if client_meta_data:
        payload.update({'clientMetadata': client_meta_data})
    payload = json.dumps(payload)
    sail_point.headers.update({'Accept': 'application/json'})
    return sail_point.sp_auth.make_rest_call('/v3/access-requests', payload=payload, headers=sail_point.headers,
                                             method='POST')


def revoke_request(config, params):
    return access_request(config, params, 'REVOKE_ACCESS')


def grant_request(config, params):
    return access_request(config, params, 'GRANT_ACCESS')


supported_operation = {
    'get_accounts': get_accounts,
    'get_account_details': get_account_details,
    'get_account_activities': get_account_activities,
    'get_account_activity': get_account_activity,
    'get_password_info': get_password_info,
    'reset_password': reset_password,
    'enable_account': enable_account,
    'disable_account': disable_account,
    'unlock_account': unlock_account,
    'revoke_request': revoke_request,
    'grant_request': grant_request
}
