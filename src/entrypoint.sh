#!/bin/sh

cd ${APP_HOME}
. venv/bin/activate
python src/edge_ngsi_dispatcher.py $@
