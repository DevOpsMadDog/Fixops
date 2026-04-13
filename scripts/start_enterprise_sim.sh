#!/bin/bash
# Start all enterprise simulation services via Docker
# Each service runs locally — no paid accounts required.
#
# Usage:
#   bash scripts/start_enterprise_sim.sh
#
# After services start (~30-60s), run the ALDECI enterprise connectors:
#   python -m pytest tests/test_enterprise_sim_services.py -v
#
# Stop all services:
#   docker rm -f aldeci-wazuh aldeci-shuffle aldeci-thehive aldeci-netbox

set -e

echo "Starting ALDECI enterprise simulation services..."
echo ""

# 1. Wazuh SIEM (port 55000)
echo "[1/4] Starting Wazuh SIEM (wazuh/wazuh-single:4.8.0)..."
docker run -d \
  --name aldeci-wazuh \
  -p 55000:55000 \
  -e WAZUH_API_USERS='[{"username":"wazuh","password":"wazuh"}]' \
  wazuh/wazuh-single:4.8.0 || echo "  -> aldeci-wazuh already running or failed (check: docker ps)"

# 2. Shuffle SOAR (port 3001)
echo "[2/4] Starting Shuffle SOAR (ghcr.io/shuffle/shuffle:latest)..."
docker run -d \
  --name aldeci-shuffle \
  -p 3001:3001 \
  ghcr.io/shuffle/shuffle:latest || echo "  -> aldeci-shuffle already running or failed (check: docker ps)"

# 3. TheHive (port 9000)
echo "[3/4] Starting TheHive 5 (strangebee/thehive:5)..."
docker run -d \
  --name aldeci-thehive \
  -p 9000:9000 \
  strangebee/thehive:5 || echo "  -> aldeci-thehive already running or failed (check: docker ps)"

# 4. NetBox CMDB (port 8080)
echo "[4/4] Starting NetBox CMDB (netboxcommunity/netbox:latest)..."
docker run -d \
  --name aldeci-netbox \
  -p 8080:8080 \
  -e SECRET_KEY=aldeci-sim \
  -e ALLOWED_HOSTS="*" \
  -e DB_HOST="" \
  netboxcommunity/netbox:latest || echo "  -> aldeci-netbox already running or failed (check: docker ps)"

echo ""
echo "Enterprise services starting..."
echo "Wait ~30-60 seconds for initialization, then:"
echo ""
echo "  Check status:      docker ps --filter name=aldeci"
echo "  View logs:         docker logs aldeci-wazuh"
echo "  Run tests:         python -m pytest tests/test_enterprise_sim_services.py -v"
echo "  Stop all:          docker rm -f aldeci-wazuh aldeci-shuffle aldeci-thehive aldeci-netbox"
echo ""
echo "Endpoints:"
echo "  Wazuh SIEM:  https://localhost:55000  (user: wazuh / wazuh)"
echo "  Shuffle SOAR: http://localhost:3001"
echo "  TheHive:      http://localhost:9000"
echo "  NetBox CMDB:  http://localhost:8080"
echo "  ntfy.sh:      https://ntfy.sh (public — no Docker needed)"
