#!/bin/bash
set -e

# Abnemo Uninstall Script for Ubuntu
# This script removes Abnemo and cleans up all installed files

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation directories
INSTALL_DIR="/opt/abnemo"
LOG_DIR="/var/log/abnemo"
DATA_DIR="/var/lib/abnemo"
CONFIG_DIR="/etc/abnemo"
ENV_FILE="${CONFIG_DIR}/abnemo.env"
SERVICE_FILE="/etc/systemd/system/abnemo.service"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Abnemo Uninstall Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if Abnemo is installed
if [ ! -d "$INSTALL_DIR" ] && [ ! -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Warning: Abnemo does not appear to be installed${NC}"
    echo -e "${YELLOW}No files found at $INSTALL_DIR or $SERVICE_FILE${NC}"
    exit 0
fi

# Confirmation prompt
echo -e "${YELLOW}WARNING: This will completely remove Abnemo from your system.${NC}"
echo -e "${YELLOW}The following will be deleted:${NC}"
echo -e "  - Service: $SERVICE_FILE"
echo -e "  - Installation: $INSTALL_DIR"
echo -e "  - Configuration: $CONFIG_DIR"
echo -e "  - Logs: $LOG_DIR"
echo ""
echo -e "${RED}Data directory will be preserved: $DATA_DIR${NC}"
echo -e "${YELLOW}You can manually delete it later if needed.${NC}"
echo ""
read -p "Are you sure you want to continue? (yes/NO): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${GREEN}Uninstall cancelled${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}Step 1: Stopping Abnemo service...${NC}"
if systemctl is-active --quiet abnemo; then
    systemctl stop abnemo
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo -e "${YELLOW}Service is not running${NC}"
fi

echo ""
echo -e "${GREEN}Step 2: Disabling Abnemo service...${NC}"
if systemctl is-enabled --quiet abnemo 2>/dev/null; then
    systemctl disable abnemo
    echo -e "${GREEN}✓ Service disabled${NC}"
else
    echo -e "${YELLOW}Service is not enabled${NC}"
fi

echo ""
echo -e "${GREEN}Step 3: Removing systemd service file...${NC}"
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    echo -e "${GREEN}✓ Service file removed: $SERVICE_FILE${NC}"
else
    echo -e "${YELLOW}Service file not found${NC}"
fi

systemctl daemon-reload
systemctl reset-failed abnemo 2>/dev/null || true

echo ""
echo -e "${GREEN}Step 4: Removing installation directory...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}✓ Installation directory removed: $INSTALL_DIR${NC}"
else
    echo -e "${YELLOW}Installation directory not found${NC}"
fi

echo ""
echo -e "${GREEN}Step 5: Removing configuration directory...${NC}"
if [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    echo -e "${GREEN}✓ Configuration directory removed: $CONFIG_DIR${NC}"
else
    echo -e "${YELLOW}Configuration directory not found${NC}"
fi

echo ""
echo -e "${GREEN}Step 6: Removing log directory...${NC}"
if [ -d "$LOG_DIR" ]; then
    rm -rf "$LOG_DIR"
    echo -e "${GREEN}✓ Log directory removed: $LOG_DIR${NC}"
else
    echo -e "${YELLOW}Log directory not found${NC}"
fi

echo ""
echo -e "${GREEN}Step 7: Removing backup directories...${NC}"
BACKUP_COUNT=$(find /opt -maxdepth 1 -type d -name "abnemo.backup.*" 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 0 ]; then
    find /opt -maxdepth 1 -type d -name "abnemo.backup.*" -exec rm -rf {} \;
    echo -e "${GREEN}✓ Removed $BACKUP_COUNT backup director(y/ies)${NC}"
else
    echo -e "${YELLOW}No backup directories found${NC}"
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Uninstall Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "${YELLOW}Data directory preserved:${NC} $DATA_DIR"
echo -e "${YELLOW}To remove data directory:${NC} sudo rm -rf $DATA_DIR"
echo ""
echo -e "${YELLOW}System packages were NOT removed.${NC}"
echo -e "${YELLOW}To remove installed packages, run:${NC}"
echo -e "  sudo apt-get remove python3-scapy python3-dnspython python3-tabulate python3-bpfcc python3-flask python3-flaskext.wtf python3-watchdog python3-cryptography python3-jwt python3-debugpy python3-flask-limiter"
echo ""
echo -e "${GREEN}Abnemo has been successfully uninstalled from your system.${NC}"
echo ""
