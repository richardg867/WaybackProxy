# Dockerfile
#
# Project: WaybackProxy
# License: GNU GPLv3
#

FROM python:3

MAINTAINER richardg867
LABEL description = "HTTP Proxy for tunneling requests through the Internet Archive Wayback Machine"

# Setup config.py
ENV LISTEN_PORT=8888
ENV DATE='20011025'
ENV DATE_TOLERANCE=365
ENV GEOCITIES_FIX=True
ENV QUICK_IMAGES=True
ENV WAYBACK_API=True
ENV CONTENT_TYPE_ENCODING=True
ENV SILENT=False
ENV SETTINGS_PAGE=True

ADD startup.sh /
ADD error.html /
ADD lrudict.py /
ADD waybackproxy.py /

EXPOSE 8080

CMD [ "sh" , "/startup.sh" ]
