#!/bin/bash
# Start Quarkus with e2e profile (H2 database) for e2e tests
# Also starts the example OAuth client on port 3333
set -x  # Enable debug output
echo "Starting abnemo for e2e tests..."
echo "Working directory: $(pwd)"

cd ..

# Source environment file
source /w/abstratium-abnemo.env

# Setup test traffic logs directory
echo "Setting up test traffic logs..."
sudo mkdir -p /tmp/e2e_traffic_logs
sudo cp e2e-tests/fixtures/test_traffic.json /tmp/e2e_traffic_logs/traffic_log_20251231_230000.json
sudo chmod 644 /tmp/e2e_traffic_logs/traffic_log_20251231_230000.json
echo "Test traffic log copied to /tmp/e2e_traffic_logs/"

# Start server (this will run in foreground)
# Use /tmp/e2e_traffic_logs as the traffic log directory with 30-year retention
exec sudo ./scripts/abnemo.sh monitor --web --web-port 40002 --log-level DEBUG --log-dir /tmp/e2e_traffic_logs --log-retention-days 10950 2>&1
