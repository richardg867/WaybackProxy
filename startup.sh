#!/bin/sh

echo LISTEN_PORT=$LISTEN_PORT > /config.py
echo DATE=$DATE >> /config.py
echo DATE_TOLERANCE=$DATE_TOLERANCE >> /config.py
echo GEOCITIES_FIX=$GEOCITIES_FIX  >> /config.py
echo QUICK_IMAGES=$QUICK_IMAGES  >> /config.py
echo WAYBACK_API=$WAYBACK_API  >> /config.py
echo CONTENT_TYPE_ENCODING=$CONTENT_TYPE_ENCODING  >> /config.py
echo SILENT=$SILENT  >> /config.py
echo SETTINGS_PAGE=$SETTINGS_PAGE  >> /config.py

echo config.py:
cat /config.py

python /waybackproxy.py
