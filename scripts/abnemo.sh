#!/bin/bash
# Abnemo wrapper script - handles sudo with correct Python path

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Get the project root (parent of scripts directory)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Find the Python executable (prefer virtual environment if active)
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON="$VIRTUAL_ENV/bin/python3"
else
    PYTHON=$(which python3)
fi

# Optional environment file that exports ABSTRAUTH_* vars
ENV_FILE="/w/abstratium-abnemo.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
fi

# Check if we need sudo for the monitor command

"$PYTHON" "$PROJECT_ROOT/src/abnemo.py" "$@"
