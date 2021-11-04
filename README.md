# Docker compose file

*docker-compose.override.yaml*:

```yaml
services:
  ngsi-dispatcher:
    image: tdmproject/edge-ngsi-dispatcher
    container_name: tdm_ngsi_dispatcher
    depends_on:
      - mosquitto
    networks:
      - tdm_edge
    volumes:
      - ./configs/tdm/:/opt/configs/
    environment:
      - SENSORS_DEFINITION_FILE=/opt/configs/sensors.json
    command: --config /opt/configs/ngsi-dispatcher.conf
    restart: always

networks:
  tdm_edge:
    external:
      name: tdm_edge
```

*ngsi-dispatcher.conf*:
```ini
logging_level="INFO"
mqtt_local_host="mosquitto"
mqtt_local_port=1883
ngsi_remote_host="<REMOTE_ORION_HOST>"
# ngsi_remote_port=1026
# ngsi_remote_user="none"
# ngsi_remote_pass="none"
ngsi_remote_token="<OAUTH2_TOKEN>"
ngsi_remote_https="<True|False>"
```

*sensors.json*:
```json
{
    "<DEVICE_ID_1>": {
        "id": "<DEVICE_ID_1>",
        "entity-name": "urn:ngsi:Entity_Name_1",
        "fiware-service": "<FIWARE_SERVICE>",
        "fiware-servicepath": "<FIWARE_SERVICEPATH>"
    },
    "<DEVICE_ID_2>": {
        "id": "<DEVICE_ID_2>",
        "entity-name": "urn:ngsi:Entity_Name_2",
        "fiware-service": "<FIWARE_SERVICE>",
        "fiware-servicepath": "<FIWARE_SERVICEPATH>"
    }
}
```

```
Usage: edge_ngsi_dispatcher.py [OPTIONS]

Options:
  --logging-level [DEBUG|INFO|WARNING|ERROR|CRITICAL]
  --mqtt-local-host TEXT          hostname or address of the local broker
                                  [env var: MQTT_LOCAL_HOST;default:
                                  localhost]
  --mqtt-local-port INTEGER       port of the local broker  [env var:
                                  MQTT_LOCAL_PORT;default: 1883]
  --ngsi-remote-host TEXT         hostname or address of the remote NGSI
                                  serviceData forwarding is disabled if not
                                  set  [env var: NGSI_REMOTE_HOST]
  --ngsi-remote-port INTEGER      port of the remote NGSI service  [env var:
                                  NGSI_REMOTE_PORT;default: 1026]
  --ngsi-remote-user TEXT         username to use for the remote NGSI service.
                                  Currently NOT IMPLEMENTED: use
                                  authentication token instead  [env var:
                                  NGSI_REMOTE_USER]
  --ngsi-remote-pass TEXT         password to use for the remote NGSI service.
                                  Currently NOT IMPLEMENTED: use
                                  authentication token instead  [env var:
                                  NGSI_REMOTE_PASS]
  --ngsi-remote-token TEXT        authentication token to use for the remote
                                  NGSI service  [env var: NGSI_REMOTE_TOKEN]
  --ngsi-remote-https             use HTTPS for remote NGSI service  [env var:
                                  NGSI_REMOTE_HTTPS;default: False]
  --sensors-definition-file FILENAME
                                  json file with the definition of the sensors
                                  [env var: SENSORS_DEFINITION_FILE;required]
  --config FILE                   Read configuration from FILE.
  --help                          Show this message and exit.
```
