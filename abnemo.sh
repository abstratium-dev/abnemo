#!/bin/bash
# Abnemo wrapper script - handles sudo with correct Python path

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Find the Python executable (prefer user's Python if available)
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
elif command -v conda &> /dev/null && [ -n "$CONDA_PREFIX" ]; then
    PYTHON="$CONDA_PREFIX/bin/python3"
elif [ -f "$HOME/miniconda3/bin/python3" ]; then
    PYTHON="$HOME/miniconda3/bin/python3"
elif [ -f "$HOME/anaconda3/bin/python3" ]; then
    PYTHON="$HOME/anaconda3/bin/python3"
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
