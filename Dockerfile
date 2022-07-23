# Dockerfile
#
# Project: WaybackProxy
# License: GNU GPLv3
#

FROM python:3

MAINTAINER richardg867
LABEL description = "HTTP Proxy for tunneling requests through the Internet Archive Wayback Machine"
WORKDIR /app
COPY . /app

# Setup config.json
ARG LISTEN_PORT=8888
ARG DATE=20011025
ARG DATE_TOLERANCE=365
ARG GEOCITIES_FIX=true
ARG QUICK_IMAGES=true
ARG WAYBACK_API=true
ARG CONTENT_TYPE_ENCODING=true
ARG SILENT=false
ARG SETTINGS_PAGE=true

EXPOSE ${LISTEN_PORT}

CMD [ "sh" , "/app/startup.sh" ]
#CMD [ "python" , "/app/waybackproxy.py" ]
