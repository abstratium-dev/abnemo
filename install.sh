#!/bin/bash
set -e

# Abnemo Installation Script for Ubuntu
# This script installs Abnemo as a systemd service

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
echo -e "${GREEN}Abnemo Installation Script${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if Ubuntu
if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    echo -e "${YELLOW}Warning: This script is designed for Ubuntu. It may not work on other distributions.${NC}"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Function to prompt for input with default value
prompt_with_default() {
    local var_name=$1
    local prompt_text=$2
    local default_value=$3
    local is_secret=$4
    
    if [ -n "$default_value" ]; then
        echo -e "${YELLOW}${prompt_text}${NC}"
        echo -e "  Default: ${GREEN}${default_value}${NC}"
    else
        echo -e "${YELLOW}${prompt_text}${NC}"
    fi
    
    if [ "$is_secret" = "true" ]; then
        read -s -p "  Enter value (or press Enter for default): " input_value
        echo
    else
        read -p "  Enter value (or press Enter for default): " input_value
    fi
    
    if [ -z "$input_value" ]; then
        eval "$var_name='$default_value'"
    else
        eval "$var_name='$input_value'"
    fi
}

echo -e "${GREEN}Step 1: Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    git \
    python3 \
    python3-pip \
    python3-scapy \
    python3-dnspython \
    python3-tabulate \
    python3-bpfcc \
    python3-bcc \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    iptables \
    ufw

echo ""
echo -e "${GREEN}Step 2: Cloning Abnemo repository...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Warning: $INSTALL_DIR already exists. Removing...${NC}"
    rm -rf "$INSTALL_DIR"
fi

git clone "$REPO_URL" "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo ""
echo -e "${GREEN}Step 3: Installing Python dependencies...${NC}"
pip3 install -r requirements.txt

echo ""
echo -e "${GREEN}Step 4: Building eBPF program...${NC}"
chmod +x scripts/build_ebpf.sh
./scripts/build_ebpf.sh

echo ""
echo -e "${GREEN}Step 5: Creating directories...${NC}"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$CONFIG_DIR"

echo ""
echo -e "${GREEN}Step 6: Configuring environment variables...${NC}"
echo -e "${YELLOW}Please provide the following configuration values:${NC}"
echo ""

# OAuth/Authentication configuration
echo -e "${GREEN}=== OAuth/Authentication Configuration ===${NC}"
prompt_with_default ABSTRAUTH_CLIENT_ID "ABSTRAUTH_CLIENT_ID" "" false
prompt_with_default ABSTRAUTH_CLIENT_SECRET "ABSTRAUTH_CLIENT_SECRET" "" true
prompt_with_default ABSTRAUTH_AUTHORIZATION_ENDPOINT "ABSTRAUTH_AUTHORIZATION_ENDPOINT" "https://auth-t.abstratium.dev/oauth2/authorize" false
prompt_with_default ABSTRAUTH_TOKEN_ENDPOINT "ABSTRAUTH_TOKEN_ENDPOINT" "https://auth-t.abstratium.dev/oauth2/token" false
prompt_with_default ABSTRAUTH_REDIRECT_URI "ABSTRAUTH_REDIRECT_URI" "http://localhost:40002/oauth/callback" false
prompt_with_default ABSTRAUTH_COOKIE_SECURE "ABSTRAUTH_COOKIE_SECURE" "true" false
prompt_with_default ABSTRAUTH_SESSION_TTL "ABSTRAUTH_SESSION_TTL" "900" false
prompt_with_default ABSTRAUTH_REQUIRED_GROUPS "ABSTRAUTH_REQUIRED_GROUPS" "abstratium-abnemo_user" false

echo ""
echo -e "${GREEN}=== SMTP Email Configuration ===${NC}"
prompt_with_default ABNEMO_SMTP_HOST "ABNEMO_SMTP_HOST" "mail.maxant.ch" false
prompt_with_default ABNEMO_SMTP_PORT "ABNEMO_SMTP_PORT" "587" false
prompt_with_default ABNEMO_SMTP_USERNAME "ABNEMO_SMTP_USERNAME" "" false
prompt_with_default ABNEMO_SMTP_PASSWORD "ABNEMO_SMTP_PASSWORD" "" true
prompt_with_default ABNEMO_SMTP_FROM "ABNEMO_SMTP_FROM" "" false
prompt_with_default ABNEMO_SMTP_TO "ABNEMO_SMTP_TO" "" false
prompt_with_default ABNEMO_SMTP_TLS "ABNEMO_SMTP_TLS" "true" false

echo ""
echo -e "${GREEN}Step 7: Writing environment file...${NC}"
cat > "$ENV_FILE" <<EOF
# Abnemo Environment Configuration
# Generated on $(date)

# OAuth/Authentication
ABSTRAUTH_CLIENT_ID=${ABSTRAUTH_CLIENT_ID}
ABSTRAUTH_CLIENT_SECRET=${ABSTRAUTH_CLIENT_SECRET}
ABSTRAUTH_AUTHORIZATION_ENDPOINT=${ABSTRAUTH_AUTHORIZATION_ENDPOINT}
ABSTRAUTH_TOKEN_ENDPOINT=${ABSTRAUTH_TOKEN_ENDPOINT}
ABSTRAUTH_REDIRECT_URI=${ABSTRAUTH_REDIRECT_URI}
ABSTRAUTH_COOKIE_SECURE=${ABSTRAUTH_COOKIE_SECURE}
ABSTRAUTH_SESSION_TTL=${ABSTRAUTH_SESSION_TTL}
ABSTRAUTH_REQUIRED_GROUPS=${ABSTRAUTH_REQUIRED_GROUPS}

# SMTP Email Configuration
ABNEMO_SMTP_HOST=${ABNEMO_SMTP_HOST}
ABNEMO_SMTP_PORT=${ABNEMO_SMTP_PORT}
ABNEMO_SMTP_USERNAME=${ABNEMO_SMTP_USERNAME}
ABNEMO_SMTP_PASSWORD=${ABNEMO_SMTP_PASSWORD}
ABNEMO_SMTP_FROM=${ABNEMO_SMTP_FROM}
ABNEMO_SMTP_TO=${ABNEMO_SMTP_TO}
ABNEMO_SMTP_TLS=${ABNEMO_SMTP_TLS}

# Python
PYTHONUNBUFFERED=1
EOF

chmod 600 "$ENV_FILE"
echo -e "${GREEN}Environment file created at: $ENV_FILE${NC}"

echo ""
echo -e "${GREEN}Step 8: Creating systemd service...${NC}"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Abnemo Network Traffic Monitor
After=network.target
Documentation=https://github.com/abstratium-dev/abnemo

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}

# Main command
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/src/abnemo.py monitor \\
    --log-dir ${DATA_DIR} \\
    --web \\
    --web-port 40002 \\
    --isp-cache-ttl 72 \\
    --continuous-log-interval 60 \\
    --log-retention-days 30 \\
    --log-max-size-mb 500 \\
    --log-level WARNING

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5

# Resource limits
MemoryLimit=512M
CPUQuota=50%

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=abnemo

# Security hardening
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR} ${INSTALL_DIR}

# Environment
EnvironmentFile=${ENV_FILE}

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Systemd service file created at: $SERVICE_FILE${NC}"

echo ""
echo -e "${GREEN}Step 9: Setting permissions...${NC}"
chmod +x "${INSTALL_DIR}/scripts/abnemo.sh"
chown -R root:root "$INSTALL_DIR"
chown -R root:root "$LOG_DIR"
chown -R root:root "$DATA_DIR"
chown -R root:root "$CONFIG_DIR"

echo ""
echo -e "${GREEN}Step 10: Enabling and starting service...${NC}"
systemctl daemon-reload
systemctl enable abnemo
systemctl start abnemo

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}Installation Complete!${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo -e "Service status:"
systemctl status abnemo --no-pager || true
echo ""
echo -e "${GREEN}Useful commands:${NC}"
echo -e "  ${YELLOW}Check status:${NC}       sudo systemctl status abnemo"
echo -e "  ${YELLOW}View logs:${NC}          sudo journalctl -u abnemo -f"
echo -e "  ${YELLOW}Restart service:${NC}    sudo systemctl restart abnemo"
echo -e "  ${YELLOW}Stop service:${NC}       sudo systemctl stop abnemo"
echo -e "  ${YELLOW}Edit config:${NC}        sudo nano $ENV_FILE"
echo ""
echo -e "${GREEN}Web interface:${NC}        http://localhost:40002"
echo ""
echo -e "${YELLOW}Note: After editing $ENV_FILE, restart the service with:${NC}"
echo -e "  sudo systemctl restart abnemo"
echo ""
