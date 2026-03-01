# Conda Setup Guide for Abnemo

## The Problem You Encountered

When you ran `./build_ebpf.sh`, it failed with "BCC Python module not found" even though you had installed `python3-bpfcc` via apt.

### Why This Happened

1. **You're in a conda environment** (`(base)` in your prompt)
2. **System packages install to system Python** (`/usr/bin/python3`)
3. **Conda uses its own Python** (`/home/ant/miniconda3/bin/python3`)
4. **The build script uses `python3`** which points to conda's Python, not system Python

```
System Python (/usr/bin/python3)
  └── Has BCC installed ✓

Conda Python (/home/ant/miniconda3/bin/python3)  ← You are here
  └── No BCC installed ✗
```

## The Solution: environment.yml + System Packages

I created `environment.yml` which specifies pip dependencies for the conda environment:

```yaml
name: abnemo
channels:
  - conda-forge
  - defaults
dependencies:
  - python>=3.7
  - pip
  - pip:
    - scapy>=2.5.0      # Can be installed via pip
    - dnspython>=2.4.0  # Can be installed via pip
    - tabulate>=0.9.0   # Can be installed via pip

# BCC must be installed separately via system package manager
```

### Why BCC Cannot Be in environment.yml or requirements.txt

**BCC is NOT available in conda or pip** because it requires:
- Kernel headers matching your running kernel
- LLVM/Clang compiler toolchain
- System-level BPF libraries
- Kernel module compilation tools

These dependencies are too complex for pip to handle, and conda-forge doesn't provide BCC packages. **You must use system package manager** (apt/dnf).

### Why conda-forge Is a Channel, Not a Package

- **Channels** are package repositories (like apt repositories)
- **conda-forge** is a community-maintained channel with 20,000+ packages
- You specify it with `-c conda-forge` when installing
- In `environment.yml`, it's listed under `channels:`, not `dependencies:`

## How to Use It

### Fresh Setup (Recommended)

```bash
# 1. Create the conda environment
conda env create -f environment.yml
conda activate abnemo

# 2. Install BCC system package
sudo apt install python3-bpfcc  # Ubuntu/Debian
# OR
sudo dnf install python3-bcc    # Fedora/RHEL

# 3. Deactivate conda to use system Python with BCC
conda deactivate
# If you see (base) still, deactivate again:
conda deactivate

# 4. Verify you're using system Python (not conda)
which python3
# Should show: /usr/bin/python3 (NOT miniconda3)

# 5. Install Python dependencies system-wide for eBPF
# Option A: Use system packages (recommended)
sudo apt install python3-scapy python3-dnspython python3-tabulate

# Option B: Use pip (if system packages are outdated)
sudo pip3 install --break-system-packages scapy dnspython tabulate

# 6. Verify BCC is installed
python3 -c "import bcc; print('BCC version:', bcc.__version__)"

# 7. Build and test eBPF
./build_ebpf.sh
```

### Update Existing Environment

If you're already in the `(base)` environment:

```bash
# Install pip dependencies in conda
pip install -r requirements.txt

# BCC is already installed system-wide (you did this earlier)
# Just deactivate conda to use it
conda deactivate

# Test
./build_ebpf.sh
```

## Understanding the Workflow

### For Regular Monitoring (Without eBPF)

```bash
conda activate abnemo              # Use conda environment
./abnemo.sh monitor                # Works! Uses conda's Python
```

### For eBPF Monitoring

```bash
# Fully deactivate conda (may need to run twice)
conda deactivate
conda deactivate  # Run again if (base) still shows

# Verify system Python
which python3  # Should be /usr/bin/python3

# Build and run eBPF
./build_ebpf.sh                    # Works! Uses system Python with BCC
sudo python3 abnemo.py monitor --ebpf  # Works!
```

### What Doesn't Work

```bash
# In conda environment with eBPF
conda activate abnemo
./build_ebpf.sh                    # FAILS! BCC not in conda ✗
```

## Quick Reference

### Check Which Python You're Using

```bash
which python3
# /home/ant/miniconda3/bin/python3  ← Conda
# /usr/bin/python3                  ← System
```

### Test BCC Installation

```bash
# Test current environment
python3 -c "import bcc"

# Test system Python specifically
/usr/bin/python3 -c "import bcc"

# Test conda Python specifically
/home/ant/miniconda3/bin/python3 -c "import bcc"
```

### Install Commands Comparison

| Package | Conda Command | Pip Command | System Package |
|---------|---------------|-------------|----------------|
| BCC | ❌ Not available | ❌ Not available | `apt install python3-bpfcc` |
| Scapy | `conda install scapy` | `pip install scapy` | `apt install python3-scapy` |
| dnspython | `conda install dnspython` | `pip install dnspython` | `apt install python3-dnspython` |

## Benefits of Using environment.yml

1. **Reproducible**: Anyone can recreate your exact environment
2. **Documented**: All dependencies in one place
3. **Cross-platform**: Works on different Linux distributions
4. **Isolated**: Doesn't interfere with system Python
5. **Complete**: Includes both conda and pip packages

## Common Questions

### Q: Can I use pip install -r requirements.txt in conda?

**A:** Yes! Conda environments include pip. But for BCC, you must use system packages:

```bash
conda activate abnemo
pip install -r requirements.txt     # ✓ Works for scapy, dnspython, tabulate
pip install bcc                     # ✗ Won't work - BCC not on PyPI
conda install -c conda-forge bcc    # ✗ Won't work - BCC not in conda-forge
sudo apt install python3-bpfcc      # ✓ This is the only way
```

### Q: Why not just use system packages for everything?

**A:** You can, but:
- Harder to manage different projects with different dependencies
- Risk of version conflicts
- Harder to share/reproduce environment
- System package versions may be outdated

### Q: Do I need to deactivate conda every time I use eBPF?

**A:** Yes. BCC is only available via system packages, so you must use system Python (`/usr/bin/python3`) for eBPF mode. For regular monitoring without eBPF, you can stay in conda.

## Important: Conda Base Auto-Activation

By default, conda auto-activates the `(base)` environment when you open a shell. This means you need to run `conda deactivate` **twice** to fully exit conda:

```bash
(abnemo) $ conda deactivate
(base) $ conda deactivate      # Need to deactivate base too!
$ which python3
/usr/bin/python3               # Now using system Python ✓
```

**To disable base auto-activation** (recommended for this project):

```bash
conda config --set auto_activate_base false
```

Then restart your shell. Now `conda deactivate` only needs to run once.

## Troubleshooting

### "BCC not found" error even after deactivating conda

**Problem**: You ran `conda deactivate` but still in `(base)` environment.

**Solution**: Deactivate again, or disable base auto-activation:

```bash
# Quick fix: deactivate twice
conda deactivate
conda deactivate

# Permanent fix: disable base auto-activation
conda config --set auto_activate_base false
# Then restart your shell
```

### "BCC not found" error

```bash
# BCC is not available in conda - use system package
sudo apt install python3-bpfcc

# Then deactivate conda before using eBPF
conda deactivate
./build_ebpf.sh
```

### "ModuleNotFoundError: No module named 'scapy'" when using eBPF

```bash
# If using system Python for eBPF, install system packages
sudo apt install python3-scapy python3-dnspython python3-tabulate

# Or if you need newer versions
sudo pip3 install --break-system-packages scapy dnspython tabulate
```

### "externally-managed-environment" error

**Problem**: Modern Ubuntu/Debian prevents `pip install` system-wide.

**Solution**: Use apt packages or override with `--break-system-packages`:

```bash
# Recommended: Use system packages
sudo apt install python3-scapy python3-dnspython python3-tabulate

# Alternative: Override (safe for these packages)
sudo pip3 install --break-system-packages scapy dnspython tabulate
```

### Build script works, but abnemo.py fails

```bash
# Make sure you're in the same environment
conda activate abnemo

# Verify all packages
python3 -c "import bcc, scapy, dns; print('All modules OK')"
```
