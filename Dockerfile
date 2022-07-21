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
ARG DATE

# Setup config.py
ENV LISTEN_PORT=8888
#ENV DATE=20011025
ENV DATE_TOLERANCE=365
ENV GEOCITIES_FIX=true
ENV QUICK_IMAGES=true
ENV WAYBACK_API=true
ENV CONTENT_TYPE_ENCODING=true
ENV SILENT=false
ENV SETTINGS_PAGE=true

EXPOSE 8888

CMD [ "sh" , "/app/startup.sh" ]
#CMD [ "python" , "/app/waybackproxy.py" ]
