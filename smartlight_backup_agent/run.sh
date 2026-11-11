#!/usr/bin/with-contenv bashio

set -e

echo "===================================="
echo " SmartLight Backup Agent"
echo " Starting..."
echo "===================================="

python3 -u /app/main.py
