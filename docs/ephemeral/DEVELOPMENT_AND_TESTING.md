# Development and Testing Guide

This document describes how to set up a development environment, run tests, and contribute to Abnemo.

## Table of Contents

1. [Development Setup](#development-setup)
2. [Running Tests](#running-tests)
3. [Code Coverage](#code-coverage)
4. [Testing Philosophy](#testing-philosophy)
5. [eBPF Development](#ebpf-development)
6. [Code Quality](#code-quality)
7. [Continuous Integration](#continuous-integration)

---

## Development Setup

### Prerequisites

- Linux operating system (Ubuntu/Debian recommended)
- Python 3.7 or higher
- Root/sudo access (for packet capture and eBPF)
- Git

### Installing Dependencies

#### 1. System Packages (Required)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-dev

# For eBPF support
sudo apt install python3-bpfcc linux-headers-$(uname -r)
```

#### 2. Python Dependencies

**Production dependencies:**
```bash
# System packages
sudo apt install python3-scapy python3-dnspython python3-tabulate python3-flask python3-flask-wtf python3-watchdog python3-cryptography python3-jwt python3-debugpy python3-flask-limiter
```

**Development dependencies:**
```bash
# Install testing and development tools
pip install -r requirements-dev.txt
```

This installs:
- `pytest` - Testing framework
- `pytest-cov` - Code coverage plugin
- `pytest-mock` - Mocking utilities
- `flake8` - Code linter
- `black` - Code formatter
- `mypy` - Type checker

#### 3. Verify Installation

```bash
# Check Python dependencies
python3 -c "import scapy, dns, flask; print('✓ Core dependencies OK')"

# Check eBPF support (optional)
python3 -c "import bcc; print('✓ BCC installed')"

# Check test dependencies
python3 -m pytest --version
```

---

## Running Tests

### Quick Start

```bash
# Run all tests
python3 -m pytest

# Run with verbose output
python3 -m pytest -v

# Run specific test file
python3 -m pytest tests/test_web_server.py

# Run specific test class
python3 -m pytest tests/test_web_server.py::TestParseLogTimestamp

# Run specific test
python3 -m pytest tests/test_web_server.py::TestParseLogTimestamp::test_parse_iso_format_with_utc_z
```

### Test Organization

```
tests/
├── __init__.py
├── test_web_server.py          # Web server and API tests
├── test_packet_monitor.py      # Packet monitoring tests (future)
├── test_process_tracker.py     # Process tracking tests (future)
├── fixtures/                   # Test data and fixtures
│   └── sample_logs/           # Sample traffic log files
└── conftest.py                # Shared pytest fixtures (future)
```

### Test Markers

Tests can be marked with categories:

```bash
# Run only unit tests
python3 -m pytest -m unit

# Skip slow tests
python3 -m pytest -m "not slow"

# Run only integration tests
python3 -m pytest -m integration

# Skip tests requiring root
python3 -m pytest -m "not requires_root"

# Skip tests requiring eBPF
python3 -m pytest -m "not requires_ebpf"
```

---

## Code Coverage

### Measuring Coverage

```bash
# Run tests with coverage report
python3 -m pytest --cov=. --cov-report=term-missing

# Generate HTML coverage report
python3 -m pytest --cov=. --cov-report=html

# Open HTML report in browser
xdg-open htmlcov/index.html
```

### Coverage Goals

- **Target**: 80% overall coverage
- **Critical modules**: 90%+ coverage
  - `web_server.py`
  - `packet_monitor.py`
  - `process_tracker.py`

### Coverage Configuration

Coverage settings are in `.coveragerc`:

```ini
[run]
source = .
omit = */tests/*, */venv/*, */__pycache__/*

[report]
precision = 2
show_missing = True
exclude_lines =
    pragma: no cover
    def __repr__
    if __name__ == .__main__.:
```

### Current Coverage Status

```bash
# Check current coverage
python3 -m pytest --cov=web_server --cov-report=term-missing tests/test_web_server.py
```

**web_server.py**: ~55% coverage (17/17 tests passing)
- Covered: `parse_log_timestamp()`, `get_logs_in_range()`
- Not covered: Flask routes (requires integration tests)

---

## eBPF Development

### Building eBPF Module

The eBPF module requires compilation and validation before use.

#### Build Script

```bash
# Run the build script
./scripts/build_ebpf.sh
```

**What it does:**
1. Checks kernel version (requires 4.x+)
2. Verifies BPF support in kernel
3. Checks Python version
4. Validates BCC installation
5. Checks Python dependencies
6. Validates eBPF C program syntax
7. Test compiles the eBPF program

#### Build Requirements

- **Kernel**: Linux 4.x or higher (5.x recommended)
- **BCC**: BPF Compiler Collection
- **Kernel headers**: `linux-headers-$(uname -r)`
- **LLVM/Clang**: For eBPF compilation

#### Manual Build Steps

If `build_ebpf.sh` fails, debug with:

```bash
# 1. Check kernel version
uname -r  # Should be 4.x+

# 2. Check BPF support
zgrep CONFIG_BPF /proc/config.gz
# Should show: CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y

# 3. Check BCC installation
python3 -c "import bcc; print(bcc.__version__)"

# 4. Test compile eBPF program
python3 << 'EOF'
from bcc import BPF
with open('ebpf/network_monitor.c') as f:
    bpf = BPF(text=f.read())
print("✓ Compilation successful")
bpf.cleanup()
EOF
```

### eBPF Code Structure

```
ebpf/
├── __init__.py
├── network_monitor.c       # eBPF C program (kernel space)
├── ebpf_loader.py         # BCC loader (user space)
└── README.md              # eBPF-specific docs
```

**Key files:**
- `network_monitor.c` - Kernel-level hooks for `tcp_sendmsg()`, `udp_sendmsg()`
- `ebpf_loader.py` - Python wrapper to load and manage eBPF program

### Testing eBPF

eBPF tests require root privileges and cannot be easily mocked.

**Approach:**
1. **Unit test** the Python wrapper (`ebpf_loader.py`) with mocked BCC
2. **Integration test** with real eBPF (requires root, marked `@pytest.mark.requires_root`)
3. **Manual testing** for full validation

**Example test structure:**
```python
@pytest.mark.requires_ebpf
@pytest.mark.requires_root
def test_ebpf_captures_traffic():
    """Integration test for eBPF packet capture"""
    # This test requires: sudo pytest -m requires_ebpf
    pass
```

### Debugging eBPF

```bash
# Enable BCC debug output
export BCC_DEBUG=1

# Run with verbose logging
sudo python3 src/abnemo.py monitor --summary-interval 5 --log-level DEBUG

# Check kernel logs
sudo dmesg | tail -50

# List loaded BPF programs
sudo bpftool prog list

# Inspect BPF maps
sudo bpftool map list
```

---

## Code Quality

### Linting

```bash
# Run flake8 linter
flake8 *.py tests/

# Check specific file
flake8 web_server.py

# Auto-fix with black
black *.py tests/
```

### Type Checking

```bash
# Run mypy type checker
mypy *.py

# Ignore missing imports
mypy --ignore-missing-imports *.py
```

### Code Formatting

```bash
# Format all Python files
black *.py tests/

# Check formatting without changes
black --check *.py
```

### Pre-commit Hooks

Create `.git/hooks/pre-commit`:
```bash
#!/bin/bash
# Run tests before commit
python3 -m pytest tests/
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi
```

Make executable:
```bash
chmod +x .git/hooks/pre-commit
```

---

## Continuous Integration

### GitHub Actions (Future)

Example `.github/workflows/test.yml`:
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      - name: Install dependencies
        run: |
          pip install -r requirements-dev.txt
      - name: Run tests
        run: |
          pytest --cov=. --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

---

## Common Issues

### Issue: Tests fail with "ModuleNotFoundError"

**Solution:**
```bash
# Ensure you're in the project root
cd /path/to/abnemo

# Install dependencies
pip install -r requirements-dev.txt

# Run tests from project root
python3 -m pytest
```

### Issue: eBPF tests fail

**Solution:**
```bash
# Skip eBPF tests
pytest -m "not requires_ebpf"

# Or install BCC
sudo apt install python3-bpfcc
```

### Issue: Coverage report not generated

**Solution:**
```bash
# Install pytest-cov
pip install pytest-cov

# Run with coverage
pytest --cov=. --cov-report=html
```

---

## Contributing

### Workflow

1. **Fork** the repository
2. **Create branch**: `git checkout -b feature/my-feature`
3. **Write tests** for new functionality
4. **Implement** the feature
5. **Run tests**: `pytest`
6. **Check coverage**: `pytest --cov=.`
7. **Lint code**: `flake8 *.py`
8. **Format code**: `black *.py`
9. **Commit**: `git commit -m "Add feature X"`
10. **Push**: `git push origin feature/my-feature`
11. **Create Pull Request**

### Code Review Checklist

- [ ] Tests added for new functionality
- [ ] All tests passing
- [ ] Coverage ≥80% for new code
- [ ] Code follows PEP 8 style
- [ ] Docstrings added for public functions
- [ ] No hardcoded values (use constants/config)
- [ ] Error handling implemented
- [ ] Documentation updated

---

## Resources

- **pytest documentation**: https://docs.pytest.org/
- **BCC documentation**: https://github.com/iovisor/bcc
- **eBPF guide**: https://ebpf.io/
- **Python testing best practices**: https://realpython.com/pytest-python-testing/
- **Code coverage**: https://coverage.readthedocs.io/

---

## Quick Reference

```bash
# Development setup
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Build eBPF
./scripts/build_ebpf.sh

# Format code
black *.py tests/

# Lint code
flake8 *.py tests/

# Type check
mypy *.py
```
