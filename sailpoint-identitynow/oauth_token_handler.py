import json
import requests
from base64 import b64encode, b64decode
from configparser import RawConfigParser
from datetime import datetime
from os import path
from time import time, ctime
from connectors.core.connector import get_logger, ConnectorError
from requests import exceptions as req_exceptions

logger = get_logger('sailpoint-identitynow')

REFRESH_TOKEN_FLAG = False
CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False
    configfile = path.join(path.dirname(path.abspath(__file__)), 'config.conf')

token_resp = {
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiI1OGViMDZhNC1kY2Q3LTRlOTYtOGZhYy1jY2EyYWZjMDNlNjEiLCJpbnRlcm5hbCI6ZmFsc2UsInBvZCI6ImNvb2siLCJvcmciOiJuZWlsLXRlc3QiLCJpZGVudGl0eV9pZCI6ImZmODA4MTgxNTVmZThjMDgwMTU1ZmU4ZDkyNWIwMzE2IiwidXNlcl9uYW1lIjoic2xwdC5zZXJ2aWNlcyIsInN0cm9uZ19hdXRoIjp0cnVlLCJhdXRob3JpdGllcyI6WyJPUkdfQURNSU4iXSwiZW5hYmxlZCI6dHJ1ZSwiY2xpZW50X2lkIjoiZmNjMGRkYmItMTA1Yy00Y2Q3LWI5NWUtMDI3NmNiZTQ1YjkwIiwiYWNjZXNzVHlwZSI6Ik9GRkxJTkUiLCJzdHJvbmdfYXV0aF9zdXBwb3J0ZWQiOmZhbHNlLCJ1c2VyX2lkIjoiNTk1ODI2Iiwic2NvcGUiOlsicmVhZCIsIndyaXRlIl0sImV4cCI6MTU2NTg5MTA2MywianRpIjoiOTQ5OWIyOTktOTVmYS00N2ZiLTgxNWMtODVkNWY2YjQzZTg2In0.zJYfjIladuGHoLXr92EOJ3A9qGNkiG5UJ9eqrtSYXAQ",
  "token_type": "bearer",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZW5hbnRfaWQiOiI1OGViMDZhNC1kY2Q3LTRlOTYtOGZhYy1jY2EyYWZjMDNlNjEiLCJpbnRlcm5hbCI6ZmFsc2UsInBvZCI6ImNvb2siLCJvcmciOiJuZWlsLXRlc3QiLCJpZGVudGl0eV9pZCI6ImZmODA4MTgxNTVmZThjMDgwMTU1ZmU4ZDkyNWIwMzE2IiwidXNlcl9uYW1lIjoic2xwdC5zZXJ2aWNlcyIsInN0cm9uZ19hdXRoIjp0cnVlLCJhdXRob3JpdGllcyI6WyJPUkdfQURNSU4iXSwiZW5hYmxlZCI6dHJ1ZSwiY2xpZW50X2lkIjoiZmNjMGRkYmItMTA1Yy00Y2Q3LWI5NWUtMDI3NmNiZTQ1YjkwIiwiWYNjZXNzVHlwZSI6Ik9GRkxJTkUiLCJzdHJvbmdfYXV0aF9zdXBwb3J0ZWQiOmZhbHNlLCJ1c2VyX2lkIjoiNTk1ODI2Iiwic2NvcGUiOlsicmVhZCIsIndyaXRlIl0sImF0aSI6Ijk0OTliMjk5LTk1ZmEtNDdmYi04MTVjLTg1ZDVmNmI0M2U4NiIsImV4cCI6MTU2NTk3NjcxMywianRpIjoiODliODk1ZDMtNTdlNC00ZDAwLWI5ZjctOTFlYWVjNDcxMGQ3In0.pfDcB0sGChdHk-oDNmiIxsKFLxq9CcPQV5-eXWgIcp4",
  "expires_in": 749,
  "scope": "read write",
  "accessType": "OFFLINE",
  "tenant_id": "58eb06a4-dcd7-4e96-8fac-cca2afc03e61",
  "internal": False,
  "pod": "cook",
  "strong_auth_supported": False,
  "org": "example",
  "user_id": "595826",
  "identity_id": "ff80818155fe8c080155fe8d925b0316",
  "strong_auth": False,
  "enabled": False,
  "jti": "9499b299-95fa-47fb-815c-85d5f6b43e86"
}
error_msgs = {
    400: 'Client Error - Returned if the request body is invalid.',
    401: 'Unauthorized - Returned if there is no authorization header, or if the JWT token is expired.',
    403: "Forbidden - Returned if the user you are running as, doesn't have access to this end-point.",
    404: 'Not Found – The specified resource could not be found.',
    429: 'Too Many Requests - Returned in response to too many requests in a given period of time - rate limited. '
         'The Retry-After header in the response includes how long to wait before trying again.',
    500: 'Internal Server Error– We had a problem with our server. Try again later.'
}


class SailPointOAuth(object):
    def __init__(self, config):
        self.base_url = config.get('server_url', '').strip('/')
        if not self.base_url.startswith('https://') and not self.base_url.startswith('http://'):
            self.base_url = 'https://' + self.base_url
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.verify_ssl = config.get('verify_ssl', False)
        self.refresh_token = None

    def make_rest_call(self, endpoint, params={}, payload={}, headers=None, method='GET'):
        service_endpoint = '{0}{1}'.format(self.base_url, endpoint)
        logger.error("service_endpoint: {0}".format(service_endpoint))
        logger.error("Rest API Payload: {0}".format(payload))
        logger.error("Rest API params: {0}".format(params))
        try:
            response = requests.request(method=method, url=service_endpoint, data=payload, params=params,
                                        headers=headers, verify=self.verify_ssl)
            logger.error("API Response Status Code: {0}".format(response.status_code))
            logger.error("API Response: {0}".format(response.text))
            if response.ok:
                return response.json()
            if response.status_code in error_msgs.keys():
                message = "{0}: {1}".format(error_msgs.get(response.status_code), response.text)
                logger.error(message)
                raise ConnectorError(message)
            else:
                msg = json.loads(response.text)
                logger.exception(msg)
                raise ConnectorError(msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(err)
            raise ConnectorError(str(err))

    def generate_token(self, refresh_token_flag):
        ts_now = time()
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        if self.refresh_token and refresh_token_flag:
            payload = {'grant_type': 'refresh_token', 'client_id': self.client_id,
                       'client_secret': self.client_secret, 'refresh_token': self.refresh_token}

        else:
            payload = {'grant_type': 'client_credentials', 'client_id': self.client_id,
                       'client_secret': self.client_secret}
        #token_resp = self.make_rest_call('/oauth/token', payload=payload, headers=headers,
        #                                 method='POST')
        token_resp['expires_in'] = (ts_now + token_resp['expires_in']) if token_resp.get("expires_in") else None
        return token_resp

    def encode_token(self, token):
        try:
            token = token.encode('UTF-8')
            return b64encode(token)
        except Exception as err:
            logger.error(err)

    def convert_ts_epoch(self, ts):
        try:
            datetime_object = datetime.strptime(ctime(ts), '%a %b %d %H:%M:%S %Y')
        except:
            datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')

        return datetime_object.timestamp()

    def validate_token(self, connector_config, connector_info):
        if CONFIG_SUPPORTS_TOKEN:
            ts_now = time()
            if not connector_config.get('access_token'):
                logger.error('Error occurred while connecting server: Unauthorized')
                raise ConnectorError('Error occurred while connecting server: Unauthorized')
            expires = connector_config['expires_in']
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                refresh_token_flag = True
                logger.debug("Token expired at {0}".format(expires))
                self.refresh_token = connector_config["refresh_token"]
                token_resp = self.generate_token(refresh_token_flag)
                errors = token_resp.get("errors")
                if errors:
                    raise ConnectorError(token_resp)
                connector_config['access_token'] = token_resp['access_token']
                connector_config['expires_in'] = token_resp['expires_in']
                connector_config['refresh_token'] = token_resp.get('refresh_token')

                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         connector_config,
                                         connector_config['config_id'])

                return "Bearer {0}".format(connector_config.get('access_token'))
            else:
                logger.debug("Token is valid till {0}".format(expires))
                return "Bearer {0}".format(connector_config.get('access_token'))
        else:
            client_id = connector_config.get('client_id')
            section_header = 'SailPoint-IdentityNow-Auth-{0}'.format(client_id)
            time_key = ['expires_in']
            token_key = ['access_token']
            try:
                config = self.handle_config(section_header)
                ts_now = time()
                expires = config.get(section_header, 'expires_in')
                if ts_now > float(expires):
                    refresh_token_flag = True
                    self.refresh_token = config.get(section_header, 'refresh_token')
                    logger.info("Token expired at {0}".format(str(expires)))
                    new_token = self.generate_token(refresh_token_flag)
                    for key, val in new_token.items():
                        if key in time_key:
                            config.set(section_header, str(key), self.convert_ts_epoch(new_token.get(key)))
                        if key in token_key:
                            config.set(section_header, str(key), self.encode_token(new_token[key]).decode('utf-8'))

                    with open(configfile, 'w') as fobj:
                        config.write(fobj)
                else:
                    logger.info("Token is valid till {0}".format(str(expires)))

                encoded_token = config.get(section_header, 'access_token')
                decoded_token = b64decode(encoded_token.encode('utf-8'))
                token = "Bearer {0}".format(decoded_token.decode('utf-8'))
                return token
            except Exception as err:
                logger.error("{0}".format(str(err)))
                raise ConnectorError("{0}".format(str(err)))

    def handle_config(self, section_header, flag=False):
        # Lets setup the config parser.
        config = RawConfigParser()
        try:
            if path.exists(configfile) is False:
                token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                return self.write_config(token_resp, config, section_header)
            else:
                # Read existing config
                config.read(configfile)
                # Check for user
                if not config.has_section(section_header) and not flag:
                    # Write new config
                    token_resp = self.generate_token(REFRESH_TOKEN_FLAG)
                    return self.write_config(token_resp, config, section_header)
                else:
                    if flag:
                        config.remove_section(section_header)
                        with open(configfile, "w") as f:
                            config.write(f)
                    else:
                        config.read(config)
                return config

        except Exception as err:
            logger.error("Handle_config:Failure {0}".format(str(err)))
            raise ConnectorError(str(err))

    def write_config(self, token_resp, config, section_header):
        time_key = ['expires_in']
        token_key = ['access_token']

        config.add_section(section_header)
        for key, val in token_resp.items():
            if key not in time_key and key not in token_key:
                config.set(section_header, str(key), str(val))
        for key in time_key:
            config.set(section_header, str(key), self.convert_ts_epoch(token_resp['expires_in']))
        for key in token_key:
            config.set(section_header, str(key), self.encode_token(token_resp[key]).decode('utf-8'))

        try:
            with open(configfile, 'w') as fobj:
                config.write(fobj)
                fobj.close()
            return config
        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))

    def remove_config(self):
        try:
            section_header = 'SailPoint-IdentityNow-Auth-{0}'.format(self.client_id)
            self.handle_config(section_header, flag=True)
        except Exception as err:
            logger.error("{0}".format(str(err)))
            raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        tq_auth = SailPointOAuth(config)
        connector_info = config.pop('connector_info', '')
        if CONFIG_SUPPORTS_TOKEN:
            if not 'access_token' in config:
                token_resp = tq_auth.generate_token(REFRESH_TOKEN_FLAG)
                config['access_token'] = token_resp.get('access_token')
                config['expires_in'] = token_resp.get('expires_in')
                config['refresh_token'] = token_resp.get('refresh_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         config,
                                         config['config_id'])
                return True
            else:
                token_resp = tq_auth.validate_token(config, connector_info)
                return True
        else:
            tq_auth.remove_config()
            client_id = config.get('client_id')
            section_header = 'SailPoint-IdentityNow-Auth-{0}'.format(client_id)
            tq_auth.handle_config(section_header)
            return True
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))
