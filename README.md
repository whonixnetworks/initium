<p align="center">
  <img src="initium.png" alt="Initium Logo" width="200"/>
</p>

<p align="center">
  <b>Initium</b> <br/>
  <i>/ɪˈnɪtiəm/</i> <br/>
  <small><i>noun</i></small> <br/>
  <i>"the beginning;"</i>
</p>

---

## Overview

This bash script automates the initial configuration, hardening, and developer tooling setup for Debian-based Linux environments. It serves as an opinionated bootstrap for fresh systems, providing an interactive interface to enable or skip specific components based on current requirements.

The script performs idempotent operations that prepare workstations or servers for development and general administration, integrating local configuration files and custom binaries into the system where appropriate.

### Key Characteristics
- Interactive, modular installation flow
- Sensible security defaults for SSH and firewall configuration
- Opinionated developer tooling stack (Docker, Node.js, Git, Zsh, Tmux)
- Optional GPU driver and firmware provisioning
- Local codebase integration for user configurations

---

## Functionality

### System Hardening
- **IPv6 Security**: Disables IPv6 support in UFW to simplify firewall rules
- **SSH Hardening**:
  - Disables password-based authentication
  - Disables direct root login
  - Enforces public key authentication
  - Restarts SSH service to apply changes

### Package Management
- **System Updates**: Updates APT repositories and upgrades base packages
- **CLI Tool Suite**: Installs comprehensive command-line utilities including:
  - **Monitoring**: `btop`, `htop`, `iotop`, `iftop`, `speedtest-cli`
  - **File Management**: `mc`, `p7zip-full`, `rsync`, `wipe`
  - **Networking**: `ufw`, `wireguard`, `openssh-server`, `ipcalc`
  - **Developer Tools**: `git`, `gh`, `fzf`, `jq`, `figlet`, `lolcat`, `snapd`
- **Containerization**: Installs Docker and Docker Compose with proper user permissions

### Driver & Firmware Installation
- **GPU Support**: Optionally configures Nvidia Container Toolkit and `nvidia-docker2`
- **System Firmware**:
  - Installs `linux-firmware` and `firmware-linux` packages
  - Configures CPU microcode (`intel-microcode` / `amd64-microcode`)
  - Sets up `fwupd` for device firmware management
  - Automatically installs recommended proprietary drivers

### Development Environment
- **Node.js**: Installs NVM and latest LTS Node.js version
- **Environment Setup**: Configures NVM in appropriate shell startup files
- **Python Tooling**: Ensures Python 3, pip, and development libraries are available



### Shell & Terminal Customization
- **Zsh Environment**:
  - Installs and configures Oh My Zsh
  - Adds syntax highlighting and autosuggestions plugins
  - Sets Zsh as default login shell
- **Tmux Configuration**:
  - Custom prefix key (Ctrl-s)
  - Mouse support and 256-color terminal
  - Detailed status line with session information
  - Custom keybindings for pane management and clipboard integration
- **Powerline Setup**:
  - Installs Powerline via pipx
  - Ensures powerline-compatible fonts are available
  - Applies custom fonts from theme directory

### Asset Deployment
- **Configuration Files**:
  - Copies user-specific aliases and configurations
  - Deploys Midnight Commander configuration
  - Applies custom Vim, Zsh, and theme configurations
- **System Integration**:
  - Installs local scripts to `/usr/local/bin`
  - Refreshes font cache for custom fonts
  - Ensures proper directory structure exists

### Finalization
- **System Cleanup**: Performs final update, upgrade, autoremove, and autoclean
- **Installation Summary**: Displays concise report of installed components
- **Reboot Option**: Prompts for optional reboot to apply driver and firmware changes

---

## Changelog

### v2.4.0 (2026-04-16)
- **Fixed**: Unquoted `$pid` variable in spinner functions (`kill`, `wait`, `spinner` calls)
- **Fixed**: Redundant `2>&1` redirect in tmux source-file check (`&>` already covers both streams)
- **Fixed**: Duplicate `# Ubuntu drivers` comment in driver installation function
- **Cleaned**: Removed stale blank sections left from removed features (cloud storage, desktop environment)
- **Note**: Configuration variables `BACKUP_DIR`, `CONFIG_DIR`, `LOG_FILE`, `MAX_RETRIES`, `TIMEOUT_SECONDS` remain defined for CLI argument support but are not yet consumed by functions
- **Note**: Docker repository codename is hardcoded to `noble` (Ubuntu 24.04)

### v2.3.0 (2026-04-16)
- **Removed**: Cloud storage (Rclone) configuration functionality
- **Removed**: GitHub authentication and SSH key management
- **Removed**: Git global configuration
- **Removed**: Desktop environment installation (XFCE4)
- **Focus**: Streamlined to core system setup, hardening, and developer tooling

### v2.2.0 (2026-04-16)
- Initial cleanup of identity management and desktop environment features

### v2.1.0 (2026-04-16)
- Original comprehensive system setup script

---

## Design Philosophy

This script follows several key design principles:

1. **Modularity**: Each component can be enabled or disabled independently
2. **Idempotency**: Can be run multiple times without causing conflicts
3. **Safety-Conscious**: Includes safety checks and preserves existing configurations
4. **User-Centric**: Prioritizes user experience with interactive prompts and clear feedback
5. **Integration Ready**: Designed to work with existing codebase structures and workflows

The script aims to provide a consistent, secure, and productive environment while maintaining flexibility for different use cases and preferences.