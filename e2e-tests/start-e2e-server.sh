#!/bin/bash
# Start Quarkus with e2e profile (H2 database) for e2e tests
# Also starts the example OAuth client on port 3333
set -x  # Enable debug output
echo "Starting abnemo for e2e tests..."
echo "Working directory: $(pwd)"

cd ..

# Start server (this will run in foreground)
exec sudo ./scripts/abnemo.sh monitor --web --web-port 40002 --log-level DEBUG 2>&1
