#!/bin/bash
# Abnemo wrapper script - handles sudo with correct Python path

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Find the Python executable (prefer virtual environment if active)
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
else
    PYTHON=$(which python3)
fi

# Check if we need sudo for the monitor command
if [[ "$1" == "monitor" ]]; then
    echo "[*] Running with sudo using Python: $PYTHON"
    sudo "$PYTHON" "$SCRIPT_DIR/abnemo.py" "$@"
else
    "$PYTHON" "$SCRIPT_DIR/abnemo.py" "$@"
fi
