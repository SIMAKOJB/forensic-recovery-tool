# 🔬 Forensic Data Recovery Tool

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Android-blue)]()
[![Python](https://img.shields.io/badge/python-3.7%2B-green)]()
[![License](https://img.shields.io/badge/license-MIT-orange)]()
[![Status](https://img.shields.io/badge/status-active-success)]()

Cross-platform forensic data recovery tool for computers, flash drives, and mobile devices.

## ✨ Features

- 🔍 **Recover deleted files** from computers (HDD/SSD)
- 💾 **USB & External drives** recovery
- 📱 **Android device** recovery (ADB + Termux)
- 📄 **30+ file types** supported
- 🔐 **SHA-256 verification** for recovered files
- 📊 **HTML reports** generation
- 🌍 **Cross-platform** (Linux, Android, macOS, Windows)

## 🚀 Quick Installation

### Linux:
```bash
git clone https://github.com/SIMAKOJB/forensic-recovery-tool.git
cd forensic-recovery-tool
bash install.sh
```

### Termux (Android):
```bash
pkg install git -y
git clone https://github.com/SIMAKOJB/forensic-recovery-tool.git
cd forensic-recovery-tool
bash install.sh
```

## 📖 Usage

After installation:
```bash
# Simple command
forensic

# Or run directly
python3 tools/universal_forensic_tool.py     # Linux
python tools/mobile_companion_app.py         # Termux
```

### Quick Start Examples

**Recover deleted photos:**
```bash
forensic
# Select: 2 (Quick scan)
# Select: 5 (Recover files)
```

**Scan USB drive:**
```bash
forensic
# Select: 1 (List drives)
# Select: 4 (Scan specific drive)
```

## 🎯 Tools Included

### 💻 Universal Desktop Tool
- List all storage devices
- Quick scan (Recycle Bin, Temp files)
- Deep scan (Full drive analysis)
- File type detection (magic bytes)
- Selective or bulk recovery

### 📱 Mobile Companion App
- On-device scanning (Termux)
- Quick media recovery
- Database recovery (WhatsApp, SMS)
- No computer needed

### 🔌 Android ADB Tool
- Professional mobile forensics
- USB debugging connection
- Remote device analysis
- Extract deleted data

## 📚 Documentation

- [Installation Guide](docs/INSTALL.md)
- [Usage Guide](docs/USAGE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Quick Start](docs/QUICK_START.md)

## 🔧 Requirements

- **Python 3.7+**
- **Linux:** Root access recommended
- **Android:** Termux from F-Droid
- **ADB:** For USB device forensics

## ⚖️ Legal Notice

**For legitimate data recovery only.**

✅ **Legal Uses:**
- Your own devices
- With proper authorization
- Educational purposes
- Professional forensics with consent

❌ **Illegal Uses:**
- Others' devices without permission
- Stolen devices
- Privacy violations

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📄 License

MIT License - see [LICENSE](LICENSE)

## 🆘 Support

- 📖 [Documentation](docs/)
- 🐛 [Report Issues](https://github.com/SIMAKOJB/forensic-recovery-tool/issues)
- 💬 [Discussions](https://github.com/SIMAKOJB/forensic-recovery-tool/discussions)

## 🙏 Credits

Built for legitimate data recovery and digital forensics education.

---

⭐ **Star this repo if you find it useful!**

**Made with ❤️ for data recovery**