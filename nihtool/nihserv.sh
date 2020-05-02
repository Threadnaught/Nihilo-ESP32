#!/bin/bash
python3 server.py &
./hostap.sh #host the ap
trap 'kill $(jobs -p)' EXIT #kill server
