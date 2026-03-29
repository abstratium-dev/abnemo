#!/bin/bash
set -e

# Abnemo Update Script for Ubuntu
# This script updates Abnemo by pulling the latest code and restarting the service

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Installation directories
INSTALL_DIR="/opt/abnemo"
LOG_DIR="/var/log/abnemo"
DATA_DIR="/var/lib/abnemo/traffic_logs"
CONFIG_DIR="/etc/abnemo"
ENV_FILE="${CONFIG_DIR}/abnemo.env"
SERVICE_FILE="/etc/systemd/system/abnemo.service"

# GitHub repository
REPO_URL="https://github.com/abstratium-dev/abnemo.git"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Abnemo Update Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if Abnemo is installed
if [ ! -d "$INSTALL_DIR" ]; then
    echo -e "${RED}Error: Abnemo is not installed at $INSTALL_DIR${NC}"
    echo -e "${YELLOW}Please run install.sh first${NC}"
    exit 1
fi

# Check if service exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo -e "${RED}Error: Abnemo service file not found at $SERVICE_FILE${NC}"
    echo -e "${YELLOW}Please run install.sh first${NC}"
    exit 1
fi

echo -e "${GREEN}Step 1: Stopping Abnemo service...${NC}"
systemctl stop abnemo
echo -e "${GREEN}✓ Service stopped${NC}"

echo ""
echo -e "${GREEN}Step 2: Backing up current installation...${NC}"
BACKUP_DIR="${INSTALL_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
cp -r "$INSTALL_DIR" "$BACKUP_DIR"
echo -e "${GREEN}✓ Backup created at: $BACKUP_DIR${NC}"

echo ""
echo -e "${GREEN}Step 3: Pulling latest code from GitHub...${NC}"
cd "$INSTALL_DIR"

# Store the current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

# Fetch latest changes
git fetch origin

# Pull latest changes
echo -e "${YELLOW}Pulling latest changes from branch: $CURRENT_BRANCH${NC}"
git pull origin "$CURRENT_BRANCH"

echo -e "${GREEN}✓ Code updated${NC}"

echo ""
echo -e "${GREEN}Step 4: Rebuilding eBPF program...${NC}"
chmod +x scripts/build_ebpf.sh
./scripts/build_ebpf.sh
echo -e "${GREEN}✓ eBPF program rebuilt${NC}"

echo ""
echo -e "${GREEN}Step 5: Ensuring directories exist...${NC}"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"
echo -e "${GREEN}✓ Directories verified${NC}"

echo ""
echo -e "${GREEN}Step 6: Setting permissions...${NC}"
chmod +x "${INSTALL_DIR}/scripts/abnemo.sh"
chown -R root:root "$INSTALL_DIR"
chown -R root:root "$LOG_DIR"
chown -R root:root "$DATA_DIR"
chown -R root:root "$CONFIG_DIR"
echo -e "${GREEN}✓ Permissions set${NC}"

echo ""
echo -e "${GREEN}Step 7: Reloading systemd and restarting service...${NC}"
systemctl daemon-reload
systemctl start abnemo
echo -e "${GREEN}✓ Service restarted${NC}"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Update Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "Service status:"
systemctl status abnemo --no-pager || true
echo ""
echo -e "${GREEN}Useful commands:${NC}"
echo -e "  ${YELLOW}Check status:${NC}       sudo systemctl status abnemo"
echo -e "  ${YELLOW}View logs:${NC}          sudo journalctl -u abnemo -f"
echo -e "  ${YELLOW}Restart service:${NC}    sudo systemctl restart abnemo"
echo -e "  ${YELLOW}Rollback:${NC}           sudo rm -rf $INSTALL_DIR && sudo mv $BACKUP_DIR $INSTALL_DIR && sudo systemctl restart abnemo"
echo ""
echo -e "${GREEN}Backup location:${NC}     $BACKUP_DIR"
echo -e "${YELLOW}Note: You can safely delete old backups to save space${NC}"
echo ""
