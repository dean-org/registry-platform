# Registry Platform — Agent Portal API reference registry image.
#
# The agent-facing service: issues verifiable credentials to a beneficiary who
# has authenticated at the counter via eSignet. Agents are a DISTINCT audience
# from staff — their own Keycloak realm, their own portal — so this is a separate
# image rather than routes bolted onto the staff API.
#
# Ships NO domain model. A variant registry builds FROM this image and selects
# its OWN model via REGISTRY_EXTENSION_MODULE (both coexist; no uninstall):
#
#     FROM openg2p/openg2p-registry-agent-portal-api:<version>
#     COPY <your>-extension/ /app/extension/
#     RUN pip install --no-cache-dir /app/extension
#
# Build context = repo root (so core/ and apis/ are reachable).
FROM python:3.12.11-alpine3.22

ARG FASTAPI_COMMON_REF=develop
# iam-core comes from GitLab. github.com/openg2p/iam-service was frozen on
# 2026-08-20 ("Moved to GitLab: openg2p/iam (read-only; build/publish
# disabled)"), so a build pointed there silently pins iam-core to that day
# and every later IAM change is missing from this image -- with no error.
ARG IAM_CORE_REF=develop

# cairo + its stack are needed at RUNTIME (not just to build): the printable
# credential is rendered by cairosvg from the manifestation's SVG card design.
RUN apk add --no-cache --virtual .build-deps gcc libc-dev linux-headers make \
 && apk add --no-cache bash git gettext libpq-dev libmagic \
      ca-certificates \
      cairo cairo-dev pango gdk-pixbuf libffi-dev \
      jpeg-dev zlib-dev freetype-dev  \
      && update-ca-certificates

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
# Default this image to the reference registry; a variant image overrides it.
ENV REGISTRY_EXTENSION_MODULE=openg2p_registry_reference_extension
ENV AGENT_PORTAL_WORKER_TYPE=gunicorn
ENV AGENT_PORTAL_HOST=0.0.0.0
ENV AGENT_PORTAL_PORT=8000
# Default worker count kept low (3) for predictable memory; the Helm chart
# overrides this per-deployment via AGENT_PORTAL_NO_OF_WORKERS in envVars.
ENV AGENT_PORTAL_NO_OF_WORKERS=3

CMD python3 -m openg2p_registry_agent_portal_api.main migrate; \
    ${AGENT_PORTAL_WORKER_TYPE} "openg2p_registry_agent_portal_api.main:app" --workers ${AGENT_PORTAL_NO_OF_WORKERS} --worker-class uvicorn.workers.UvicornWorker --bind ${AGENT_PORTAL_HOST}:${AGENT_PORTAL_PORT}
