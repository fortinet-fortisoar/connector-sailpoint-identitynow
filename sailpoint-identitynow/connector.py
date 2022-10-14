""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector, get_logger, ConnectorError
from .operations import supported_operation
from .oauth_token_handler import _check_health

logger = get_logger('sailpoint-identitynow')


class SailPointIdentityNowConnector(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                        "connector_version": self._info_json.get('version')}
            operation = supported_operation.get(operation)
            return operation(config, params)
        except Exception as e:
            logger.error("An exception occurred: {}".format(e))
            raise ConnectorError("An exception occurred: {}".format(e))

    def check_health(self, config):
        config['connector_info'] = {"connector_name": self._info_json.get('name'),
                                    "connector_version": self._info_json.get('version')}
        return _check_health(config)
