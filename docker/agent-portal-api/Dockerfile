FROM python:3.12.11-alpine3.22

ARG FASTAPI_COMMON_REF=develop
ARG IAM_CORE_REF=develop

RUN apk add --no-cache \
      ca-certificates \
      bash git gettext libpq-dev libmagic \
      cairo cairo-dev pango gdk-pixbuf libffi-dev \
      jpeg-dev zlib-dev freetype-dev \
 && update-ca-certificates

RUN apk add --no-cache --virtual .build-deps \
      gcc libc-dev linux-headers make

WORKDIR /app

COPY core/openg2p-registry-core /app/core/openg2p-registry-core
COPY apis/openg2p-registry-agent-portal-api /app/apis/openg2p-registry-agent-portal-api
COPY reference-extension /app/reference-extension

RUN pip install --no-cache-dir \
      "git+https://github.com/openg2p/openg2p-fastapi-common@${FASTAPI_COMMON_REF}#subdirectory=openg2p-fastapi-common" \
      "git+https://github.com/openg2p/openg2p-fastapi-common@${FASTAPI_COMMON_REF}#subdirectory=openg2p-fastapi-auth" \
      "git+https://github.com/openg2p/iam.git@${IAM_CORE_REF}#subdirectory=iam-core" \
      /app/core/openg2p-registry-core \
      /app/apis/openg2p-registry-agent-portal-api \
      /app/reference-extension \
 && apk del --no-network .build-deps

ENV PYTHONUNBUFFERED=1
ENV REGISTRY_EXTENSION_MODULE=openg2p_registry_reference_extension
ENV AGENT_PORTAL_WORKER_TYPE=gunicorn
ENV AGENT_PORTAL_HOST=0.0.0.0
ENV AGENT_PORTAL_PORT=8000
ENV AGENT_PORTAL_NO_OF_WORKERS=3

CMD cat /etc/ssl/cert.pem /opt/truststore/ca.crt > /tmp/combined-ca.crt; \
    export SSL_CERT_FILE=/tmp/combined-ca.crt; \
    python3 -m openg2p_registry_agent_portal_api.main migrate; \
    ${AGENT_PORTAL_WORKER_TYPE} "openg2p_registry_agent_portal_api.main:app" \
      --workers ${AGENT_PORTAL_NO_OF_WORKERS} \
      --worker-class uvicorn.workers.UvicornWorker \
      --bind ${AGENT_PORTAL_HOST}:${AGENT_PORTAL_PORT}
