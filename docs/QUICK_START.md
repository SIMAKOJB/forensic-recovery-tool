# Quick Start Guide

## Installation
```bash
git clone https://github.com/SIMAKOJB/forensic-recovery-tool.git
cd forensic-recovery-tool
bash install.sh
```

## First Run
```bash
forensic
```

## Common Tasks

### Recover deleted photos
```bash
forensic
# Select: 2 (Quick scan)
# Select: 5 (Recover files)
```

### Scan USB drive
```bash
forensic
# Select: 1 (List drives)
# Select: 4 (Scan specific)
```

### Generate report
```bash
forensic
# After scan: 7 (Generate report)
```

## Commands
```bash
# Update
cd forensic-recovery-tool && git pull && bash install.sh

# View logs
cat ~/forensic_recovery/forensic_log.txt

# View recovered
ls ~/forensic_recovery/

# Uninstall
rm -rf ~/forensic_tools ~/forensic-recovery-tool
```