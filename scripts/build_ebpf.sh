#!/bin/bash
#
# Build script for Abnemo eBPF module
# This script checks dependencies and validates the eBPF C program
#

set -e  # Exit on error

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Get the project root (parent of scripts directory)
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Change to project root to ensure relative paths work
cd "$PROJECT_ROOT"

echo "========================================="
echo "Abnemo eBPF Build Script"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${YELLOW}Warning: Running as root${NC}"
fi

echo "Step 1: Checking system requirements..."
echo "----------------------------------------"

# Check kernel version
KERNEL_VERSION=$(uname -r)
KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)

echo "Kernel version: $KERNEL_VERSION"

if [ "$KERNEL_MAJOR" -lt 4 ]; then
    echo -e "${RED}ERROR: Kernel 4.x or higher required for eBPF${NC}"
    echo "Your kernel: $KERNEL_VERSION"
    exit 1
fi

if [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 1 ]; then
    echo -e "${YELLOW}Warning: Kernel 4.1+ recommended, you have $KERNEL_VERSION${NC}"
fi

echo -e "${GREEN}✓ Kernel version OK${NC}"
echo ""

# Check if BPF is enabled in kernel
echo "Step 2: Checking BPF support..."
echo "----------------------------------------"

if [ -f /proc/config.gz ]; then
    if zgrep -q "CONFIG_BPF=y" /proc/config.gz && zgrep -q "CONFIG_BPF_SYSCALL=y" /proc/config.gz; then
        echo -e "${GREEN}✓ BPF enabled in kernel${NC}"
    else
        echo -e "${RED}ERROR: BPF not enabled in kernel${NC}"
        echo "Please rebuild kernel with CONFIG_BPF=y and CONFIG_BPF_SYSCALL=y"
        exit 1
    fi
elif [ -f /boot/config-$(uname -r) ]; then
    if grep -q "CONFIG_BPF=y" /boot/config-$(uname -r) && grep -q "CONFIG_BPF_SYSCALL=y" /boot/config-$(uname -r); then
        echo -e "${GREEN}✓ BPF enabled in kernel${NC}"
    else
        echo -e "${RED}ERROR: BPF not enabled in kernel${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Warning: Could not verify BPF support (config file not found)${NC}"
    echo "Assuming BPF is supported..."
fi
echo ""

# Check Python version
echo "Step 3: Checking Python..."
echo "----------------------------------------"

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}ERROR: python3 not found${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "Python version: $PYTHON_VERSION"
echo -e "${GREEN}✓ Python 3 found${NC}"
echo ""

# Check for BCC
echo "Step 4: Checking BCC (BPF Compiler Collection)..."
echo "----------------------------------------"

if python3 -c "import bcc" 2>/dev/null; then
    echo -e "${GREEN}✓ BCC Python module installed${NC}"
    BCC_VERSION=$(python3 -c "import bcc; print(bcc.__version__)" 2>/dev/null || echo "unknown")
    echo "BCC version: $BCC_VERSION"
else
    echo -e "${RED}ERROR: BCC Python module not found${NC}"
    echo ""
    echo "To install BCC:"
    echo "  Ubuntu/Debian:"
    echo "    sudo apt update"
    echo "    sudo apt install python3-bpfcc"
    echo ""
    echo "  Fedora/RHEL:"
    echo "    sudo dnf install python3-bcc"
    echo ""
    echo "  From source:"
    echo "    https://github.com/iovisor/bcc/blob/master/INSTALL.md"
    exit 1
fi
echo ""

# Check for required Python modules
echo "Step 5: Checking Python dependencies..."
echo "----------------------------------------"

MISSING_DEPS=0

for module in scapy dns; do
    if python3 -c "import $module" 2>/dev/null; then
        echo -e "${GREEN}✓ $module${NC}"
    else
        echo -e "${RED}✗ $module (missing)${NC}"
        MISSING_DEPS=1
    fi
done

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo "To install missing dependencies:"
    echo "  pip3 install scapy dnspython"
    exit 1
fi
echo ""

# Validate eBPF C program
echo "Step 6: Validating eBPF C program..."
echo "----------------------------------------"

EBPF_FILE="ebpf/network_monitor.c"

if [ ! -f "$EBPF_FILE" ]; then
    echo -e "${RED}ERROR: eBPF program not found: $EBPF_FILE${NC}"
    exit 1
fi

echo "Found: $EBPF_FILE"
FILE_SIZE=$(stat -f%z "$EBPF_FILE" 2>/dev/null || stat -c%s "$EBPF_FILE" 2>/dev/null)
echo "  File size: $FILE_SIZE bytes"

# Basic syntax check (look for required functions)
if grep -q "trace_tcp_sendmsg" "$EBPF_FILE" && \
   grep -q "trace_udp_sendmsg" "$EBPF_FILE" && \
   grep -q "BPF_PERF_OUTPUT" "$EBPF_FILE"; then
    echo -e "  ${GREEN}✓ Structure looks good${NC}"
else
    echo -e "  ${RED}ERROR: Missing required functions${NC}"
    exit 1
fi
echo ""

# Test compilation (dry run)
echo "Step 7: Test compiling eBPF program..."
echo "----------------------------------------"

echo "Compiling network_monitor.c (accurate byte counting)..."
python3 << 'EOF'
import sys
try:
    from bcc import BPF
    
    with open('ebpf/network_monitor.c', 'r') as f:
        bpf_text = f.read()
    
    bpf = BPF(text=bpf_text)
    print("✓ Compilation successful!")
    bpf.cleanup()
    sys.exit(0)
    
except Exception as e:
    print(f"✗ Compilation failed: {e}")
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ eBPF program compiles successfully${NC}"
else
    echo -e "${RED}ERROR: eBPF program failed to compile${NC}"
    echo "Check the C code for syntax errors"
    exit 1
fi
echo ""

# Summary
echo "========================================="
echo "Build Summary"
echo "========================================="
echo -e "${GREEN}✓ All checks passed!${NC}"
echo ""
echo "eBPF module is ready to use."
echo "  - Tracks actual bytes sent/received per packet"
echo "  - Provides accurate traffic measurement"
echo "  - Includes process and container identification"
echo ""
echo "Usage:"
echo "  sudo ./scripts/abnemo.sh monitor"
echo ""
echo "Or:"
echo "  sudo python3 src/abnemo.py monitor --summary-interval 10"
echo ""
echo "Note: eBPF requires root privileges to attach kernel probes."
echo "========================================="
