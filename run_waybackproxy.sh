#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

python3 "$SCRIPT_DIR/waybackproxy.py" -c "$SCRIPT_DIR/config2000.json" &

python3 "$SCRIPT_DIR/waybackproxy.py" -c "$SCRIPT_DIR/config1997.json" &

python3 "$SCRIPT_DIR/waybackproxy.py" -c "$SCRIPT_DIR/config2004.json" &

wait
