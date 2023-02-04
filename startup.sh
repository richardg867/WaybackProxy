#!/bin/sh
if [ "${LISTEN_PORT}" ]; then
    sed -i -e "s/\"LISTEN_PORT\":[^,]*/\"LISTEN_PORT\": ${LISTEN_PORT}/g" /app/config.json
fi
if [ "${DATE}" ]; then
    sed -i -e "s/\"DATE\":[^,]*/\"DATE\": \"${DATE}\"/g" /app/config.json
fi
if [ "${DATE_TOLERANCE}" ]; then
    sed -i -e "s/\"DATE_TOLERANCE\":[^,]*/\"DATE_TOLERANCE\": ${DATE_TOLERANCE}/g" /app/config.json
fi
if [ "${GEOCITIES_FIX}" ]; then
    sed -i -e "s/\"GEOCITIES_FIX\":[^,]*/\"GEOCITIES_FIX\": $GEOCITIES_FIX/g" /app/config.json
fi
if [ "${QUICK_IMAGES}" ]; then
    sed -i -e "s/\"QUICK_IMAGES\":[^,]*/\"QUICK_IMAGES\": $QUICK_IMAGES/g" /app/config.json
fi
if [ "${WAYBACK_API}" ]; then
    sed -i -e "s/\"WAYBACK_API\":[^,]*/\"WAYBACK_API\": $WAYBACK_API/g" /app/config.json
fi
if [ "${QUICK_IMAGES}" ]; then
    sed -i -e "s/\"QUICK_IMAGES\":[^,]*/\"QUICK_IMAGES\": $QUICK_IMAGES/g" /app/config.json
fi
if [ "${CONTENT_TYPE_ENCODING}" ]; then
    sed -i -e "s/\"CONTENT_TYPE_ENCODING\":[^,]*/\"CONTENT_TYPE_ENCODING\": $CONTENT_TYPE_ENCODING/g" /app/config.json
fi
if [ "${SILENT}" ]; then
    sed -i -e "s/\"SILENT\":[^,]*/\"SILENT\": $SILENT/g" /app/config.json
fi
if [ "${SETTINGS_PAGE}" ]; then
    sed -i -e "s/\"SETTINGS_PAGE\":[^,]*/\"SETTINGS_PAGE\": $SETTINGS_PAGE/g" /app/config.json
fi
echo "[-] Using this config.json file:"
cat /app/config.json
echo "\n[-] Starting proxy server"
python /app/waybackproxy.py