#!/usr/bin/env python
#
#  Copyright 2020, 2021, CRS4 - Center for Advanced Studies, Research and
#  Development in Sardinia
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
Edge Gateway Remote Dispatcher microservice for NGSI Orion Context Broker.
"""

import click
from click_config_file import configuration_option
import json
from http.client import responses
import logging
import paho.mqtt.client as mqtt
import re
import requests
import signal
import sys


APPLICATION_NAME = 'ngsi_dispatcher'
logger = logging.getLogger(APPLICATION_NAME)


TOPIC_LIST = [
    'WeatherObserved',
]


ATTRIBUTE_MAP = {
    "dateObserved": (None, None),
    "temperature": (None, None),
    "relativeHumidity": (None, None),
    "barometricPressure": ("atmosphericPressure", lambda x: float(x)/100)
}


# Supresses 'requests' library default logging
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)


def edge_serial():
    """Retrieves the serial number from the hardware platform."""
    _serial = None
    with open('/proc/cpuinfo', 'r') as _fp:
        for _line in _fp:
            _match = re.search(r'Serial\s+:\s+0+(?P<serial>\w+)$', _line)
            if _match:
                _serial = _match.group('serial').upper()
                break

    return _serial


def try_cast_to_float(value):
    try:
        return float(value)
    except ValueError:
        return value


class MQTTConnection():
    """Helper class for MQTT connection handling"""

    def __init__(self, host='localhost', port=1883, keepalive=60, logger=None,
                 userdata=None):
        # pylint: disable=too-many-arguments
        self._host = host
        self._port = port
        self._keepalive = keepalive
        self._userdata = userdata

        self._logger = logger
        if self._logger is None:
            self._logger = logger.getLoger()

        self._local_client = mqtt.Client(userdata=self._userdata)
        self._local_client.on_connect = self._on_connect
        self._local_client.on_message = self._on_message
        self._local_client.on_disconnect = self._on_disconnect

        if self._userdata['NGSI_REMOTE_HOST']:
            self._remote_relay_enabled = True
        else:
            self._remote_relay_enabled = False

    def connect(self):
        self._logger.debug("Connecting to Local MQTT broker '{:s}:{:d}'".
                           format(self._host, self._port))
        try:
            self._local_client.connect(self._host, self._port, self._keepalive)
        except Exception as ex:
            self._logger.fatal(
                "Connection to Local MQTT broker '{:s}:{:d}' failed. "
                "Error was: {:s}.".format(self._host, self._port, str(ex)))
            self._logger.fatal("Exiting.")
            sys.exit(-1)

        if self._remote_relay_enabled:
            self._logger.info(
                "NGSI host is set: remote data transmission is enabled")
        else:
            self._logger.info(
                "NGSI host is empty: remote data transmission is disabled")

        self._local_client.loop_forever()

    def signal_handler(self, signal, frame):
        self._logger.info("Got signal '{:d}': exiting.".format(signal))
        self._local_client.disconnect()

    def _on_connect(self, client, userdata, flags, rc):
        # pylint: disable=unused-argument,invalid-name
        self._logger.info(
            "Connected to MQTT broker '{:s}:{:d}' with result code {:d}".
            format(self._host, self._port, rc))

        for _topic in TOPIC_LIST:
            _topic += '/#'

            self._logger.debug("Subscribing to {:s}".format(_topic))

            (result, _) = client.subscribe(_topic)
            if result == mqtt.MQTT_ERR_SUCCESS:
                self._logger.info("Subscribed to {:s}".format(_topic))

    def _on_disconnect(self, client, userdata, rc):
        # pylint: disable=unused-argument,invalid-name
        self._logger.info("Disconnected with result code {:d}".format(rc))

    def _on_message(self, client, userdata, msg):
        # pylint: disable=unused-argument
        _message = msg.payload.decode()
        self._logger.debug(
            "Received MQTT message - topic:\'{:s}\', message:\'{:s}\'".
            format(msg.topic, _message))

        if self._remote_relay_enabled:
            _topic, _, _signal_id = msg.topic.partition('/')
            _station_id, _, _sensor_id = _signal_id.partition('.')

            fields = json.loads(_message)

            _sensors_definition = userdata['SENSORS_DEFINITION']
            if _station_id in [*_sensors_definition]:
                _entity_name = _sensors_definition[_station_id]['entity-name']
                _fiware_service = (_sensors_definition[_station_id]
                                   ['fiware-service'])
                _fiware_servicepath = (_sensors_definition[_station_id]
                                       ['fiware-servicepath'])
                data_point = {
                    "dateObserved": {
                        "value": "2020-06-08T17:54:00"  # dateObserved
                    }
                }

                # Loops on message elements and check if the given attribute
                # is a valid one
                for _f in fields:
                    if _f in [*ATTRIBUTE_MAP]:
                        # converts the attribute name and value if required
                        _name, _transform = ATTRIBUTE_MAP[_f]
                        _transform = _transform if _transform else lambda x: x
                        data_point.update({
                            _name or _f: {
                                "value": _transform(fields[_f])
                            }
                        })

                try:
                    _headers = {
                        'Fiware-Service': _fiware_service,
                        'Fiware-ServicePath': _fiware_servicepath,
                        'X-Auth-Token': userdata['NGSI_REMOTE_TOKEN'],
                        'Accept': 'application/json',
                        'Content-Type': 'application/json'
                    }

                    _server = (f"http://{userdata['NGSI_REMOTE_HOST']}:"
                               f"{userdata['NGSI_REMOTE_PORT']}")
                    _resource = f"/v2/entities/{_entity_name}/attrs"
                    _url = f"{_server}{_resource}"
                    _verb = "PATCH"
                    self._logger.debug(
                        "Sending NGSI message - header: %s, message: %s" %
                        (_headers, data_point))
                    response = requests.request(
                        _verb, _url, headers=_headers,
                        data=json.dumps(data_point))
                    _http_ver = ('HTTP/1.1' if
                                 response.raw.version == 11 else 'HTTP/1.0')
                    response.raise_for_status()
                    self._logger.info(
                        (f'{_server} "{_verb} {_resource} {_http_ver}" '
                         f'{response.status_code}'))
                except requests.exceptions.HTTPError:
                    self._logger.error(
                        (f'{_server} "{_verb} {_resource} {_http_ver}" '
                         f'{response.status_code} '
                         f'"{responses[response.status_code]}": '
                         f"{response.text}"))
                except Exception as ex:
                    self._logger.error(ex)
        else:
            self._logger.debug(
                "NGSI host is empty: remote data transmission is disabled")


@click.command()
@click.option("--logging-level", envvar="LOGGING_LEVEL",
              type=click.Choice(['DEBUG', 'INFO', 'WARNING',
                                 'ERROR', 'CRITICAL']), default='INFO')
@click.option('--mqtt-local-host', envvar='MQTT_LOCAL_HOST',
              type=str, default='localhost', show_default=True,
              show_envvar=True,
              help=('hostname or address of the local broker'))
@click.option('--mqtt-local-port', envvar='MQTT_LOCAL_PORT',
              type=int, default=1883, show_default=True, show_envvar=True,
              help=('port of the local broker'))
@click.option('--ngsi-remote-host', envvar='NGSI_REMOTE_HOST', type=str,
              show_default=True, show_envvar=True,
              help=('hostname or address of the remote NGSI service'
                    'Data forwarding is disabled if not set'))
@click.option('--ngsi-remote-port', envvar='NGSI_REMOTE_PORT',
              type=int, default=1026, show_default=True, show_envvar=True,
              help=('port of the remote NGSI service'))
@click.option('--ngsi-remote-user', envvar='NGSI_REMOTE_USER',
              type=str, show_default=True, show_envvar=True,
              help=('username to use for the remote NGSI service. '
                    'Currently NOT IMPLEMENTED: '
                    'use authentication token instead'))
@click.option('--ngsi-remote-pass', envvar='NGSI_REMOTE_PASS',
              type=str, show_default=True, show_envvar=True,
              help=('password to use for the remote NGSI service. '
                    'Currently NOT IMPLEMENTED: '
                    'use authentication token instead'))
@click.option('--ngsi-remote-token', envvar='NGSI_REMOTE_TOKEN',
              type=str, show_default=True, show_envvar=True,
              help=('authentication token to use for the remote NGSI service'))
@click.option('--sensors-definition-file', envvar='SENSORS_DEFINITION_FILE',
              type=click.File('r'), show_default=True, show_envvar=True,
              required=True,
              help=('json file with the definition of the sensors'))
@configuration_option()
@click.pass_context
def edge_ngsi_dispatcher(ctx, mqtt_local_host: str, mqtt_local_port: int,
                         ngsi_remote_host: str, ngsi_remote_port: int,
                         ngsi_remote_user: str, ngsi_remote_pass: str,
                         ngsi_remote_token: str, sensors_definition_file: str,
                         logging_level) -> None:
    _level = getattr(logging, logging_level)
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S",
        level=_level)

    logger.debug("loggin level set to %s",
                 logging_level)
    logger.debug("local broker is mqtt://%s:%d",
                 mqtt_local_host, mqtt_local_port)
    logger.info(
        "Pointing to NGSI server http://%s:%d. %s token provided.",
        ngsi_remote_host, ngsi_remote_port,
        'Auth' if ngsi_remote_token else 'No auth')

    # Checks the Python Interpeter version
    if sys.version_info < (3, 0):
        logger.fatal("This software requires Python version >= 3.0: exiting.")
        sys.exit(-1)

    sensors_definition = {}
    sensors_definition = json.load(sensors_definition_file)

    _userdata = {
        'NGSI_REMOTE_HOST': ngsi_remote_host,
        'NGSI_REMOTE_PORT': ngsi_remote_port,
        'NGSI_REMOTE_USER': ngsi_remote_user,
        'NGSI_REMOTE_PASS': ngsi_remote_pass,
        'NGSI_REMOTE_TOKEN': ngsi_remote_token,
        'SENSORS_DEFINITION': sensors_definition
    }

    connection = MQTTConnection(mqtt_local_host, mqtt_local_port,
                                logger=logger, userdata=_userdata)
    signal.signal(signal.SIGINT, connection.signal_handler)

    connection.connect()


if __name__ == "__main__":
    edge_ngsi_dispatcher()

# vim:ts=4:expandtab
