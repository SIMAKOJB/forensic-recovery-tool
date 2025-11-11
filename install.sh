#!/bin/bash
# Forensic Tool Auto-Installer
# Works on both Termux (Android) and Linux
# Usage: bash install.sh

set -e  # Exit on error

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║     🔬 FORENSIC TOOL AUTO-INSTALLER                             ║"
echo "║                                                                  ║"
echo "║     Installing forensic recovery tools...                       ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Detect environment
if [ -d "/data/data/com.termux" ]; then
    ENV="termux"
    echo "✓ Detected: Termux (Android)"
elif [ -f "/etc/os-release" ]; then
    ENV="linux"
    echo "✓ Detected: Linux"
else
    echo "❌ Unknown environment"
    exit 1
fi

echo ""

# Function to check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Step 1: Check/Install Python
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1: Checking Python installation..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command_exists python3 || command_exists python; then
    echo "✓ Python is installed"
    if command_exists python3; then
        PYTHON_CMD="python3"
    else
        PYTHON_CMD="python"
    fi
    $PYTHON_CMD --version
else
    echo "⚠️  Python not found. Installing..."
    
    if [ "$ENV" = "termux" ]; then
        pkg update -y
        pkg install python -y
        PYTHON_CMD="python"
    else
        # Linux
        if command_exists apt; then
            sudo apt update
            sudo apt install python3 python3-pip -y
        elif command_exists dnf; then
            sudo dnf install python3 python3-pip -y
        elif command_exists yum; then
            sudo yum install python3 python3-pip -y
        elif command_exists pacman; then
            sudo pacman -S python python-pip --noconfirm
        else
            echo "❌ Unable to install Python automatically"
            echo "Please install Python manually and run this script again"
            exit 1
        fi
        PYTHON_CMD="python3"
    fi
    echo "✓ Python installed successfully"
fi

echo ""

# Step 2: Setup storage (Termux only)
if [ "$ENV" = "termux" ]; then
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Step 2: Setting up storage access..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [ ! -d "$HOME/storage" ]; then
        echo "⚠️  Storage not setup. Please grant permission..."
        termux-setup-storage
        sleep 2
    fi
    
    if [ -d "/sdcard" ]; then
        echo "✓ Storage access confirmed"
    else
        echo "❌ Storage access failed"
        echo "Please run: termux-setup-storage"
        echo "And grant the permission"
    fi
    echo ""
fi

# Step 3: Create directories
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3: Creating directories..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

INSTALL_DIR="$HOME/forensic_tools"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "✓ Created: $INSTALL_DIR"
echo ""

# Step 4: Download/Create tools
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4: Installing forensic tools..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Create launcher script
cat > "$INSTALL_DIR/forensic.sh" << 'LAUNCHER_EOF'
#!/bin/bash
# Forensic Tool Launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -d "/data/data/com.termux" ]; then
    # Termux - use mobile tool
    if [ -f "$SCRIPT_DIR/mobile_companion_app.py" ]; then
        python "$SCRIPT_DIR/mobile_companion_app.py"
    else
        echo "❌ Mobile tool not found!"
        echo "Please place mobile_companion_app.py in: $SCRIPT_DIR"
    fi
else
    # Linux - use universal tool
    if [ -f "$SCRIPT_DIR/universal_forensic_tool.py" ]; then
        python3 "$SCRIPT_DIR/universal_forensic_tool.py" "$@"
    else
        echo "❌ Universal tool not found!"
        echo "Please place universal_forensic_tool.py in: $SCRIPT_DIR"
    fi
fi
LAUNCHER_EOF

chmod +x "$INSTALL_DIR/forensic.sh"
echo "✓ Created launcher script"

# Create README
cat > "$INSTALL_DIR/README.txt" << 'README_EOF'
FORENSIC TOOL INSTALLATION

📁 Location: ~/forensic_tools/

📝 Files to add:
   1. mobile_companion_app.py (for Termux/Android)
   2. universal_forensic_tool.py (for Linux)

🚀 How to run:
   
   Method 1 - Direct:
   python mobile_companion_app.py (Termux)
   python3 universal_forensic_tool.py (Linux)
   
   Method 2 - Launcher:
   ./forensic.sh
   
   Method 3 - Alias (after setup):
   forensic

📥 Getting the scripts:
   
   Option A: Copy from computer
   - Use ADB: adb push script.py /sdcard/
   - Then: cp /sdcard/script.py ~/forensic_tools/
   
   Option B: Create manually
   - Use text editor on phone
   - Save to Download folder
   - Copy to ~/forensic_tools/
   
   Option C: Type in terminal
   - nano ~/forensic_tools/script.py
   - Paste code
   - Ctrl+X, Y, Enter

✅ After adding scripts:
   chmod +x ~/forensic_tools/*.py
   ./forensic.sh

Need help? Check the installation guide!
README_EOF

echo "✓ Created README"
echo ""

# Step 5: Setup aliases
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Creating shortcuts..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Determine shell config file
if [ -f "$HOME/.bashrc" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ "$ENV" = "termux" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
    touch "$SHELL_CONFIG"
else
    SHELL_CONFIG="$HOME/.profile"
    touch "$SHELL_CONFIG"
fi

# Add alias if not exists
if ! grep -q "alias forensic=" "$SHELL_CONFIG" 2>/dev/null; then
    echo "" >> "$SHELL_CONFIG"
    echo "# Forensic Tool Shortcut" >> "$SHELL_CONFIG"
    echo "alias forensic='cd $INSTALL_DIR && ./forensic.sh'" >> "$SHELL_CONFIG"
    echo "alias forensic-update='cd $INSTALL_DIR && bash install.sh'" >> "$SHELL_CONFIG"
    echo "✓ Added 'forensic' command to $SHELL_CONFIG"
else
    echo "✓ Shortcuts already exist"
fi

# Source the config
source "$SHELL_CONFIG" 2>/dev/null || true

echo ""

# Step 6: Install dependencies
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 6: Installing dependencies..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Most dependencies are built-in, but let's verify
$PYTHON_CMD -c "import hashlib, json, pathlib" 2>/dev/null && \
    echo "✓ All required modules available" || \
    echo "⚠️  Some modules missing (but may not be needed)"

echo ""

# Installation complete
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                                                                  ║"
echo "║     ✅ INSTALLATION COMPLETE!                                    ║"
echo "║                                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "📁 Installation directory: $INSTALL_DIR"
echo ""
echo "📝 NEXT STEPS:"
echo ""
echo "1. Add the forensic tool scripts to: $INSTALL_DIR"
echo "   "
if [ "$ENV" = "termux" ]; then
    echo "   For Termux: Copy mobile_companion_app.py"
    echo "   "
    echo "   Quick method:"
    echo "   - Save script to phone's Download folder"
    echo "   - Run: cp /sdcard/Download/mobile_companion_app.py ~/forensic_tools/"
    echo "   - Run: chmod +x ~/forensic_tools/*.py"
else
    echo "   For Linux: Copy universal_forensic_tool.py"
    echo "   "
    echo "   Quick method:"
    echo "   - nano ~/forensic_tools/universal_forensic_tool.py"
    echo "   - Paste the code"
    echo "   - Save: Ctrl+X, Y, Enter"
    echo "   - Run: chmod +x ~/forensic_tools/*.py"
fi
echo ""
echo "2. Run the tool:"
echo "   - Method 1: forensic"
echo "   - Method 2: cd ~/forensic_tools && ./forensic.sh"
echo "   - Method 3: $PYTHON_CMD ~/forensic_tools/[script].py"
echo ""
echo "3. Read the README:"
echo "   cat ~/forensic_tools/README.txt"
echo ""
echo "📚 For detailed instructions, see the installation guide"
echo ""
echo "🆘 Need help?"
echo "   - Check: cat ~/forensic_tools/README.txt"
echo "   - Logs: ~/forensic_recovery/forensic_log.txt"
echo ""
echo "Thank you for installing Forensic Recovery Tool! 🔬"
echo ""

# Reminder for shell reload
if [ "$ENV" = "termux" ]; then
    echo "💡 TIP: Restart Termux or run: source ~/.bashrc"
else
    echo "💡 TIP: Restart terminal or run: source $SHELL_CONFIG"
fi
echo ""