ARG APP_HOME=/opt/ngsi-dispatcher/

# ============================================================================ #
# Development stage: used only to create the python virtual environment        #
# ============================================================================ #
FROM tdmproject/alpine-python-3:arm32v7-3.10 AS development

LABEL maintainer="Massimo Gaggero <massimo dot gaggero at crs4 dot it>"

ARG APP_HOME

COPY requirements.txt "${APP_HOME}"

# Install required packages
RUN apk add --no-cache git && \
	pip3 install --no-cache-dir virtualenv && \
	mkdir -p ${APP_HOME} && \
	cd ${APP_HOME} && \
	virtualenv venv && \
	. venv/bin/activate && \
        pip3 install --no-cache-dir -r requirements.txt

# ============================================================================ #
# Final stage: lean, intended to be used as execute container                  #
# docker build --target=final -f docker/Dockerfile \                           #
#              -t tdmproject/edge-ngsi-dispatcher.                             #
# ============================================================================ #
FROM tdmproject/alpine-python-3:arm32v7-3.10 AS final

ARG APP_HOME

ENV APP_HOME=${APP_HOME}

COPY --from=development ${APP_HOME} ${APP_HOME}
WORKDIR ${APP_HOME}

COPY src src

ENTRYPOINT ["src/entrypoint.sh"]

CMD [ "-c", "/opt/configs/tdm.conf" ]

# ============================================================================ #
# Testing Stage: final stage for testing purposes                              #
# docker build --target=test -f docker/Dockerfile \                            #
#              -t tdmproject/edge-ngsi-dispatcher.                             #
# ============================================================================ #
FROM final AS test

ARG APP_HOME

ENV APP_HOME=${APP_HOME}

WORKDIR ${APP_HOME}

COPY tests tests
