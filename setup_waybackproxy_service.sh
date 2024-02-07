#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SCRIPT_PATH="$SCRIPT_DIR/run_waybackproxy.sh"

SERVICE_FILE="waybackproxy.service"

cat << EOF | sudo tee /etc/systemd/system/$SERVICE_FILE > /dev/null
[Unit]
Description=Wayback Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $SCRIPT_PATH
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

sudo systemctl enable $SERVICE_FILE

echo "Wayback Proxy Service is installed and enabled. "
