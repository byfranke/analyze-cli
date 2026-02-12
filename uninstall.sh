#!/bin/bash
# Analyze-CLI Uninstall Script
# Copyright (c) 2026 byFranke - Security Solutions
#
# This script removes Analyze-CLI and its associated files from your system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
CONFIG_DIR="$HOME/.analyze-cli"
BACKUP_DIR="$HOME/.analyze-cli-backup-$(date +%Y%m%d-%H%M%S)"
SYSTEM_INSTALL="/usr/local/bin/analyze-cli"
CURRENT_DIR="$(dirname "$(readlink -f "$0")")"

echo -e "${CYAN}================================="
echo "  Analyze-CLI Uninstaller"
echo "=================================${NC}"
echo ""

# Function to print colored messages
print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to ask yes/no questions
ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

# Check if Analyze-CLI is installed
check_installation() {
    local installed=false

    if [ -f "$CURRENT_DIR/analyze-cli.py" ]; then
        print_info "Found Analyze-CLI in current directory"
        installed=true
    fi

    if [ -d "$CONFIG_DIR" ]; then
        print_info "Found configuration directory: $CONFIG_DIR"
        installed=true
    fi

    if [ -f "$SYSTEM_INSTALL" ]; then
        print_info "Found system-wide installation: $SYSTEM_INSTALL"
        installed=true
    fi

    if [ "$installed" = false ]; then
        print_warning "Analyze-CLI installation not found"
        echo "Nothing to uninstall."
        exit 0
    fi
}

# Backup configuration files
backup_config() {
    if [ -d "$CONFIG_DIR" ]; then
        echo ""
        if ask_yes_no "Do you want to backup your configuration files before uninstalling?"; then
            print_info "Creating backup at: $BACKUP_DIR"
            mkdir -p "$BACKUP_DIR"

            # Backup config files
            if [ -f "$CONFIG_DIR/config.ini" ]; then
                cp "$CONFIG_DIR/config.ini" "$BACKUP_DIR/" 2>/dev/null || true
                print_success "Backed up config.ini"
            fi

            if [ -f "$CONFIG_DIR/.key" ]; then
                cp "$CONFIG_DIR/.key" "$BACKUP_DIR/" 2>/dev/null || true
                print_success "Backed up encryption key"
            fi

            # Create restore script
            cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
# Restore script for Analyze-CLI configuration

BACKUP_DIR="$(dirname "$(readlink -f "$0")")"
CONFIG_DIR="$HOME/.analyze-cli"

echo "Restoring Analyze-CLI configuration..."

# Create config directory
mkdir -p "$CONFIG_DIR"

# Restore files
if [ -f "$BACKUP_DIR/config.ini" ]; then
    cp "$BACKUP_DIR/config.ini" "$CONFIG_DIR/"
    chmod 600 "$CONFIG_DIR/config.ini"
    echo "[OK] Restored config.ini"
fi

if [ -f "$BACKUP_DIR/.key" ]; then
    cp "$BACKUP_DIR/.key" "$CONFIG_DIR/"
    chmod 600 "$CONFIG_DIR/.key"
    echo "[OK] Restored encryption key"
fi

echo "Configuration restored successfully!"
EOF
            chmod +x "$BACKUP_DIR/restore.sh"

            print_success "Backup completed"
            print_info "To restore configuration later, run: $BACKUP_DIR/restore.sh"
        fi
    fi
}

# Remove system-wide installation
remove_system_install() {
    if [ -f "$SYSTEM_INSTALL" ]; then
        echo ""
        if ask_yes_no "Remove system-wide installation from /usr/local/bin?"; then
            if sudo rm -f "$SYSTEM_INSTALL"; then
                print_success "Removed system-wide installation"
            else
                print_error "Failed to remove system-wide installation (may require sudo)"
            fi
        fi
    fi
}

# Remove configuration directory
remove_config_dir() {
    if [ -d "$CONFIG_DIR" ]; then
        echo ""
        if ask_yes_no "Remove configuration directory (~/.analyze-cli)?"; then
            if rm -rf "$CONFIG_DIR"; then
                print_success "Removed configuration directory"
            else
                print_error "Failed to remove configuration directory"
            fi
        fi
    fi
}

# Remove Python dependencies
remove_dependencies() {
    echo ""
    print_warning "The following Python packages were installed by Analyze-CLI:"
    echo "  - requests"
    echo "  - rich"
    echo "  - configparser"
    echo "  - cryptography"
    echo "  - keyring"
    echo "  - getpass4"
    echo "  - GitPython"
    echo ""
    print_warning "These packages might be used by other applications"

    if ask_yes_no "Do you want to uninstall these Python packages?"; then
        print_info "Attempting to uninstall Python packages..."

        # Try to uninstall packages
        packages="requests rich configparser cryptography keyring getpass4 GitPython"

        for package in $packages; do
            echo -n "  Removing $package... "
            if pip3 uninstall -y "$package" 2>/dev/null || pip uninstall -y "$package" 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}SKIP${NC} (not installed or in use)"
            fi
        done

        print_success "Package removal completed"
    else
        print_info "Skipping Python package removal"
    fi
}

# Remove local files
remove_local_files() {
    echo ""
    print_warning "This will remove Analyze-CLI files from the current directory:"
    echo "  $CURRENT_DIR"
    echo ""
    echo "Files to be removed:"
    [ -f "$CURRENT_DIR/analyze-cli.py" ] && echo "  - analyze-cli.py"
    [ -f "$CURRENT_DIR/setup.py" ] && echo "  - setup.py"
    [ -f "$CURRENT_DIR/install.sh" ] && echo "  - install.sh"
    [ -f "$CURRENT_DIR/requirements.txt" ] && echo "  - requirements.txt"
    [ -f "$CURRENT_DIR/README.md" ] && echo "  - README.md"
    [ -f "$CURRENT_DIR/LICENSE" ] && echo "  - LICENSE"
    [ -f "$CURRENT_DIR/VERSION" ] && echo "  - VERSION"
    [ -f "$CURRENT_DIR/CHANGELOG.md" ] && echo "  - CHANGELOG.md"
    [ -f "$CURRENT_DIR/.gitignore" ] && echo "  - .gitignore"
    echo ""

    if ask_yes_no "Remove all Analyze-CLI files from current directory?"; then
        # Remove files
        rm -f "$CURRENT_DIR/analyze-cli.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/setup.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/install.sh" 2>/dev/null || true
        rm -f "$CURRENT_DIR/requirements.txt" 2>/dev/null || true
        rm -f "$CURRENT_DIR/README.md" 2>/dev/null || true
        rm -f "$CURRENT_DIR/LICENSE" 2>/dev/null || true
        rm -f "$CURRENT_DIR/VERSION" 2>/dev/null || true
        rm -f "$CURRENT_DIR/CHANGELOG.md" 2>/dev/null || true
        rm -f "$CURRENT_DIR/.gitignore" 2>/dev/null || true

        print_success "Removed local files"

        # Note about uninstall script
        print_warning "Note: This uninstall script (uninstall.sh) will remain for your records"
        print_info "You can manually delete it if desired: rm $0"
    else
        print_info "Skipping local file removal"
    fi
}

# Clean up system caches
cleanup_caches() {
    echo ""
    if ask_yes_no "Clean up Python caches and temporary files?"; then
        # Clean pip cache related to analyze-cli
        print_info "Cleaning pip cache..."
        pip3 cache purge 2>/dev/null || pip cache purge 2>/dev/null || true

        # Remove __pycache__ if exists
        if [ -d "$CURRENT_DIR/__pycache__" ]; then
            rm -rf "$CURRENT_DIR/__pycache__"
            print_success "Removed Python cache directory"
        fi

        print_success "Cache cleanup completed"
    fi
}

# Main uninstall process
main() {
    # Check if running as root (not recommended)
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended unless removing system-wide installation"
    fi

    # Check what's installed
    check_installation

    echo ""
    echo -e "${YELLOW}This will uninstall Analyze-CLI from your system.${NC}"
    echo "You will be asked to confirm each step."
    echo ""

    if ! ask_yes_no "Do you want to continue with the uninstallation?"; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    # Backup configuration
    backup_config

    # Remove system-wide installation
    remove_system_install

    # Remove configuration directory
    remove_config_dir

    # Ask about dependencies
    remove_dependencies

    # Remove local files
    remove_local_files

    # Clean up caches
    cleanup_caches

    # Final message
    echo ""
    echo -e "${GREEN}================================="
    echo "  Uninstallation Complete"
    echo "=================================${NC}"
    echo ""

    if [ -d "$BACKUP_DIR" ]; then
        print_info "Your configuration was backed up to:"
        echo "  $BACKUP_DIR"
        echo ""
        print_info "To restore it later, run:"
        echo "  $BACKUP_DIR/restore.sh"
    fi

    echo ""
    print_success "Analyze-CLI has been uninstalled"
    echo ""
    echo "Thank you for using Analyze-CLI!"
    echo "For feedback or support: support@byfranke.com"
}

# Run main function
main "$@"
