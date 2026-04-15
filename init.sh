6#!/usr/bin/env bash
# initium — Ubuntu system setup and configuration script
# author: greedy
# version: 2.1.0

set -euo pipefail

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# CONFIGURATION variables (UPPERCASE, top of file, with comments)
BACKUP_DIR="${HOME:-/home/$USER}/.initium/backups"  # Backup directory for configs
CONFIG_DIR="$HOME/.config/initium"                  # User configuration directory
LOG_FILE="/var/log/initium.log"                     # System log file location
MAX_RETRIES=3                                       # shouldn't fail after 3 attempts
TIMEOUT_SECONDS=300                                 # shouldn't hang indefinitely

# Color/style definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD="\033[1m"
DIM="\033[2m"
NC='\033[0m'

# Standard log functions
log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Styled sections & headers
show_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   $1${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
}

show_section() {
    echo -e "${MAGENTA}=== $1 ===${NC}"
}

# Error handling
die() {
    log_error "FATAL: $1"
    exit 1
}

# Help system
show_help() {
    show_header "Initium v2.1.0"

    echo -e "${CYAN}Usage:${NC}"
    echo -e "  ${WHITE}./init.sh [OPTIONS]${NC}"
    echo

    show_section "Flags"
    echo -e "  ${GREEN}✓${NC} ${WHITE}-h, --help${NC}         Show this help"
    echo -e "  ${GREEN}✓${NC} ${WHITE}-v, --version${NC}      Show version"
    echo -e "  ${YELLOW}●${NC} ${WHITE}--backup-dir DIR${NC}   Set backup directory"
    echo -e "  ${YELLOW}●${NC} ${WHITE}--config-dir DIR${NC}   Set config directory"
    echo -e "  ${BLUE}ℹ${NC} ${WHITE}--log-file FILE${NC}     Set log file location"
    echo

    show_section "Description"
    echo -e "  Interactive Ubuntu system setup script for initial configuration,"
    echo -e "  hardening, and developer tooling setup for Debian-based Linux environments."
    echo

    show_section "Examples"
    echo -e "  ${GRAY}./init.sh${NC}"
    echo -e "  ${GRAY}./init.sh --help${NC}"
    echo -e "  ${GRAY}./init.sh --backup-dir /mnt/backups${NC}"
    echo
}

# Runtime variables (lowercase, local inside functions)
USER=$(whoami)
HOME_DIR="${HOME:-/home/$USER}"
WORK_DIR="$HOME_DIR/initium"
HOSTNAME=$(hostname)
SSH_PATH="$HOME_DIR/.ssh"
THEME_CONFIGS_DIR="$WORK_DIR/theme/configs"
FONTS_DIR="$WORK_DIR/theme/fonts"
RCLONE_DIR="$HOME_DIR/.config/rclone"
RCLONE_CONF="$RCLONE_DIR/rclone.conf"
RCLONE_BAK="$RCLONE_DIR/rclone.bak"

INSTALL_STATUS=()

# spinner function
spinner() {
    local pid=$1
    local message=$2
    local spinstr='|/-\'
    local temp
    
    tput civis
    
    while kill -0 $pid 2>/dev/null; do
        temp=${spinstr#?}
        printf " ${BLUE}[%c]${NC} %s\r" "$spinstr" "$message"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
    done
    tput cnorm
    printf "\r\033[K"
    wait $pid
    return $?
}

run_with_spinner() {
    local message=$1
    shift
    local cmd="$@"
    eval "$cmd" &
    local pid=$!
    spinner $pid "$message"
    local exit_code=$?
    return $exit_code
}



get_yn() {
    local prompt="$1"
    local response
    while true; do
        read -rp "$(echo -e "${CYAN}${prompt}${NC} ${GRAY}[y/N]:${NC} ")" response
        case ${response,,} in
            y|yes) echo "y"; return ;;
            n|no|"") echo "n"; return ;;
            *) echo -e "${RED}Invalid input. Please enter y or n.${NC}" ;;
        esac
    done
}

track_status() {
    INSTALL_STATUS+=("$1")
}

# Configuration Collection
collect_configuration() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Ubuntu System Setup Script${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    
    # Base system updates
    log_info "Base system updates will always be performed"
    echo
    
    # Package installations
    echo -e "${MAGENTA}=== Package Installation ===${NC}"
    PACKAGE_INSTALL=$(get_yn "Install additional packages (htop, fzf, etc)?")
    DOCKER_INSTALL=$(get_yn "Install Docker?")
    NODE_INSTALL=$(get_yn "Install NVM & Node.js?")
    echo
    
    # Shell and development setup
    echo -e "${MAGENTA}=== Shell & Development Setup ===${NC}"
    SHELL_SETUP=$(get_yn "Setup ZSH, Tmux & Powerline?")
    echo
    
    # Git Configuration Section
    echo -e "${MAGENTA}=== Git Configuration ===${NC}"
    CONFIGURE_GIT=$(get_yn "Configure global git username & email?")
    
    if [[ "$CONFIGURE_GIT" == "y" ]]; then
        echo
        read -rp "$(echo -e "${CYAN}Git username:${NC} ")" GIT_USERNAME
        read -rp "$(echo -e "${CYAN}Git email:${NC} ")" GIT_EMAIL
        
        if [[ -z "$GIT_USERNAME" ]] || [[ -z "$GIT_EMAIL" ]]; then
            log_warning "Username or email empty, skipping git configuration"
            CONFIGURE_GIT="n"
            GIT_USERNAME=""
            GIT_EMAIL=""
        fi
    fi
    echo
    
    # GitHub Authentication Section
    echo -e "${MAGENTA}=== GitHub Configuration ===${NC}"
    SETUP_GITHUB=$(get_yn "Configure GitHub? (Web login or GPG Key)")
    
    if [[ "$SETUP_GITHUB" == "y" ]]; then
        echo
        GITHUB_METHOD=$(get_yn "Create a new SSH key and add to GitHub?")
        
        if [[ "$GITHUB_METHOD" == "y" ]]; then
            echo
            read -rp "$(echo -e "${CYAN}GitHub GPG token:${NC} ")" GITHUB_TOKEN
            
            if [[ -z "$GITHUB_TOKEN" ]]; then
                log_warning "No token provided, skipping GitHub authentication"
                SETUP_GITHUB="n"
                GITHUB_METHOD="n"
            else
                # If git config wasn't set yet, prompt for it now
                if [[ "$CONFIGURE_GIT" != "y" ]] || [[ -z "$GIT_USERNAME" ]]; then
                    echo
                    log_info "GitHub authentication requires git configuration"
                    read -rp "$(echo -e "${CYAN}Git username:${NC} ")" GIT_USERNAME
                    read -rp "$(echo -e "${CYAN}Git email:${NC} ")" GIT_EMAIL
                    
                    if [[ -n "$GIT_USERNAME" ]] && [[ -n "$GIT_EMAIL" ]]; then
                        CONFIGURE_GIT="y"
                    else
                        log_warning "Git configuration incomplete, skipping GitHub auth"
                        SETUP_GITHUB="n"
                        GITHUB_METHOD="n"
                    fi
                fi
            fi
        fi
    fi
    echo
    
    # Pull Authorized Keys Section
    echo -e "${MAGENTA}=== SSH Key Management ===${NC}"
    PULL_AUTH_KEYS=$(get_yn "Pull authorized_keys from Git provider?")
    
    if [[ "$PULL_AUTH_KEYS" == "y" ]]; then
        # Try to use existing username first
        if [[ -n "$GIT_USERNAME" ]]; then
            USE_EXISTING=$(get_yn "Use git username '$GIT_USERNAME' for keys?")
            if [[ "$USE_EXISTING" == "y" ]]; then
                KEYS_USERNAME="$GIT_USERNAME"
                log_info "Using username: $KEYS_USERNAME"
            else
                echo
                read -rp "$(echo -e "${CYAN}GitHub username for SSH keys:${NC} ")" KEYS_USERNAME
            fi
        else
            echo
            read -rp "$(echo -e "${CYAN}GitHub username for SSH keys:${NC} ")" KEYS_USERNAME
        fi
        
        if [[ -z "$KEYS_USERNAME" ]]; then
            log_warning "No username provided, skipping key import"
            PULL_AUTH_KEYS="n"
        else
            # Default provider
            KEYS_PROVIDER="github.com"
            log_info "Using default provider: $KEYS_PROVIDER"
        fi
    fi
    echo
    
    # Rclone configuration
    echo -e "${MAGENTA}=== Cloud Storage ===${NC}"
    PASTE_RCLONE=$(get_yn "Paste rclone config?")
    
    if [[ "$PASTE_RCLONE" == "y" ]]; then
        echo
        echo -e "${CYAN}Paste your rclone config and press Ctrl+D when done:${NC}"
        RCLONE_CONTENT=$(cat)
        if [[ -z "$RCLONE_CONTENT" ]]; then
            PASTE_RCLONE="n"
            log_warning "No config pasted, skipping rclone setup"
        fi
    fi
    echo
    
    # System configuration
    echo -e "${MAGENTA}=== System Configuration ===${NC}"
    DRIVER_INSTALL=$(get_yn "Install drivers & firmware?")
    DESKTOP_INSTALL=$(get_yn "Install XFCE4 desktop environment?")
    echo
}

# Configuration Summary
show_configuration_summary() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Configuration Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    
    echo -e "${CYAN}System Updates:${NC}"
    echo -e "  ${GREEN}✓${NC} Base system packages"
    echo -e "  ${GREEN}✓${NC} APT update & upgrade"
    echo
    
    echo -e "${CYAN}Optional Installations:${NC}"
    [[ "$PACKAGE_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} Additional packages" || echo -e "  ${GRAY}✗${NC} Additional packages"
    [[ "$DOCKER_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} Docker & Docker Compose" || echo -e "  ${GRAY}✗${NC} Docker & Docker Compose"
    [[ "$NODE_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} NVM & Node.js" || echo -e "  ${GRAY}✗${NC} NVM & Node.js"
    echo
    
    echo -e "${CYAN}Shell & Development:${NC}"
    [[ "$SHELL_SETUP" == "y" ]] && echo -e "  ${GREEN}✓${NC} ZSH, Tmux & Powerline" || echo -e "  ${GRAY}✗${NC} ZSH, Tmux & Powerline"
    echo
    
    echo -e "${CYAN}Git Configuration:${NC}"
    if [[ "$CONFIGURE_GIT" == "y" ]]; then
        echo -e "  ${GREEN}✓${NC} Git config ($GIT_USERNAME, $GIT_EMAIL)"
    else
        echo -e "  ${GRAY}✗${NC} Git config"
    fi
    
    if [[ "$SETUP_GITHUB" == "y" ]] && [[ "$GITHUB_METHOD" == "y" ]]; then
        echo -e "  ${GREEN}✓${NC} GitHub SSH authentication"
    else
        echo -e "  ${GRAY}✗${NC} GitHub SSH authentication"
    fi
    
    if [[ "$PULL_AUTH_KEYS" == "y" ]]; then
        echo -e "  ${GREEN}✓${NC} Pull SSH keys from $KEYS_PROVIDER ($KEYS_USERNAME)"
    else
        echo -e "  ${GRAY}✗${NC} Pull SSH keys"
    fi
    echo
    
    echo -e "${CYAN}Cloud Storage:${NC}"
    [[ "$PASTE_RCLONE" == "y" ]] && echo -e "  ${GREEN}✓${NC} Rclone configuration" || echo -e "  ${GRAY}✗${NC} Rclone configuration"
    echo
    
    echo -e "${CYAN}System Configuration:${NC}"
    [[ "$DRIVER_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} Drivers & firmware" || echo -e "  ${GRAY}✗${NC} Drivers & firmware"
    [[ "$DESKTOP_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} XFCE4 desktop environment" || echo -e "  ${GRAY}✗${NC} XFCE4 desktop environment"
    echo
    
    echo -e "${BLUE}========================================${NC}"
    echo
    
    CONFIRM=$(get_yn "Proceed with this configuration?")
    if [[ "$CONFIRM" != "y" ]]; then
        log_error "Setup cancelled by user"
        exit 0
    fi
}

# Base System Updates
update_base_system() {
    log_info "Updating base system..."
    
    if run_with_spinner "Updating APT repositories..." "sudo apt update > /dev/null 2>&1"; then
        log_success "APT repositories updated"
    else
        log_error "Failed to update repositories"
    fi
    
    if run_with_spinner "Installing base packages..." "sudo apt install -y whiptail btop unattended-upgrades software-properties-common wget curl jq ufw openssh-server ipcalc mc git nano > /dev/null 2>&1"; then
        log_success "Base packages installed"
        track_status "Base system updated"
    else
        log_error "Failed to install base packages"
        track_status "Base system: FAILED"
    fi
}

# Package Installation
install_packages() {
    [[ "$PACKAGE_INSTALL" != "y" ]] && return
    
    log_info "Installing additional packages..."
    if run_with_spinner "Installing development tools and utilities..." "sudo apt install -y dconf-cli htop gh locate fzf ansiweather wireguard cowsay wireguard-tools bc tmux snapd iotop iftop coreutils rclone rsync figlet p7zip-full wipe lolcat python3-full python3-pip speedtest-cli > /dev/null 2>&1"; then
        log_success "Additional packages installed"
        track_status "Additional packages installed"
    else
        log_error "Failed to install some packages"
        track_status "Additional packages: FAILED"
    fi
}

# Docker Install
install_docker() {
    [[ "$DOCKER_INSTALL" != "y" ]] && return

    if command -v docker >/dev/null 2>&1; then
        DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
        log_info "Docker is already installed (version $DOCKER_VERSION)"
        track_status "Docker already installed"
    else
        log_info "Docker not found, installing..."
        if run_with_spinner "Installing Docker..." "sudo apt update > /dev/null 2>&1 && sudo apt install -y docker.io > /dev/null 2>&1"; then
            sudo usermod -aG docker "$USER" > /dev/null 2>&1 || true
            log_success "Docker installed and user added to docker group"
            track_status "Docker installed"
        else
            log_error "Failed to install Docker via APT"
            track_status "Docker: FAILED"
            return
        fi
    fi
    
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null)
        log_info "Docker Compose is already installed (version $COMPOSE_VERSION)"
        track_status "Docker Compose already installed"
    else
        log_info "Docker Compose not found, installing..."
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

        if run_with_spinner "Installing Docker Compose plugin..." "sudo apt update > /dev/null 2>&1 && sudo apt install -y docker-compose-plugin > /dev/null 2>&1"; then
            COMPOSE_VERSION=$(docker compose version --short 2>/dev/null)
            log_success "Docker Compose installed (version $COMPOSE_VERSION)"
            track_status "Docker Compose added"
        else
            log_error "Failed to install Docker Compose plugin"
            track_status "Docker Compose: FAILED"
        fi
    fi
}

# Node.js Installation
install_nodejs() {
    [[ "$NODE_INSTALL" != "y" ]] && return
    
    export NVM_DIR="$HOME/.nvm"
    if [[ -s "$NVM_DIR/nvm.sh" ]]; then
        source "$NVM_DIR/nvm.sh"
        
        if command -v nvm >/dev/null 2>&1; then
            NVM_VERSION=$(nvm --version 2>/dev/null)
            log_info "NVM is already installed (version $NVM_VERSION)"
            if command -v node >/dev/null 2>&1; then
                NODE_VERSION=$(node --version 2>/dev/null)
                log_info "Node.js is already installed ($NODE_VERSION)"
                track_status "NVM & Node.js already installed ($NODE_VERSION)"
                return
            else
                log_info "Node.js not found, installing LTS version..."
                if run_with_spinner "Installing Node.js LTS..." "nvm install --lts > /dev/null 2>&1 && nvm use --lts > /dev/null 2>&1 && nvm alias default 'lts/*' > /dev/null 2>&1"; then
                    NODE_VERSION=$(node --version 2>/dev/null)
                    log_success "Node.js installed ($NODE_VERSION)"
                    track_status "Node.js added to existing NVM ($NODE_VERSION)"
                else
                    log_error "Failed to install Node.js"
                    track_status "Node.js installation: FAILED"
                fi
                return
            fi
        fi
    fi
    
    log_info "Installing NVM and Node.js..."
    if run_with_spinner "Downloading and installing NVM..." "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh 2>/dev/null | bash > /dev/null 2>&1"; then
        CONFIG_FILE="$HOME/.bashrc"
        [[ "$(basename "$SHELL")" == "zsh" ]] && [[ -f "$HOME/.zshrc" ]] && CONFIG_FILE="$HOME/.zshrc"
        
        grep -q "NVM_DIR" "$CONFIG_FILE" || cat >> "$CONFIG_FILE" << 'EOF'

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"
EOF
        
        export NVM_DIR="$HOME/.nvm"
        [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
        
        if command -v nvm >/dev/null 2>&1; then
            if run_with_spinner "Installing Node.js LTS..." "nvm install --lts > /dev/null 2>&1 && nvm use --lts > /dev/null 2>&1 && nvm alias default 'lts/*' > /dev/null 2>&1"; then
                NODE_VERSION=$(node --version 2>/dev/null)
                log_success "NVM and Node.js installed ($NODE_VERSION)"
                track_status "NVM & Node.js installed ($NODE_VERSION)"
            else
                log_success "NVM installed (Node.js installation pending)"
                track_status "NVM installed (Node.js pending)"
            fi
        else
            log_success "NVM installed (restart shell to use)"
            track_status "NVM installed (shell restart required)"
        fi
    else
        log_error "Failed to install NVM"
        track_status "NVM & Node.js: FAILED"
    fi
}

# Configure Git
configure_git() {
    [[ "$CONFIGURE_GIT" != "y" ]] || [[ -z "$GIT_USERNAME" ]] || [[ -z "$GIT_EMAIL" ]] && return
    
    log_info "Configuring Git..."
    git config --global user.name "$GIT_USERNAME" > /dev/null 2>&1
    git config --global user.email "$GIT_EMAIL" > /dev/null 2>&1
    log_success "Git configured with username and email"
    track_status "Git config set ($GIT_USERNAME, $GIT_EMAIL)"
}

# Setup GitHub Authentication
setup_github_auth() {
    [[ "$SETUP_GITHUB" != "y" ]] || [[ "$GITHUB_METHOD" != "y" ]] || [[ -z "$GITHUB_TOKEN" ]] && return
    
    log_info "Setting up GitHub authentication..."
    
    # Setup SSH
    SSH_KEY_FILE="$SSH_PATH/gh_${USER}_${HOSTNAME}"
    mkdir -p "$SSH_PATH"
    chmod 700 "$SSH_PATH"
    
    if [ ! -f "$SSH_KEY_FILE" ]; then
        ssh-keygen -t ed25519 -C "${GIT_EMAIL:-$USER@$HOSTNAME}" -f "$SSH_KEY_FILE" -N "" -q > /dev/null 2>&1
        chmod 600 "$SSH_KEY_FILE"
        chmod 644 "${SSH_KEY_FILE}.pub"
        log_success "SSH key generated"
    else
        log_info "SSH key already exists"
    fi
    
    # Add to SSH agent
    eval "$(ssh-agent -s)" > /dev/null 2>&1
    ssh-add "$SSH_KEY_FILE" > /dev/null 2>&1 || true
    
    # Configure SSH config
    if ! grep -q "Host github.com" ~/.ssh/config 2>/dev/null; then
        cat >> ~/.ssh/config << EOF

Host *
    AddKeysToAgent yes
    IdentityFile $SSH_KEY_FILE

Host github.com
    HostName github.com
    User git
    IdentityFile $SSH_KEY_FILE
    IdentitiesOnly yes

Host $HOSTNAME
    HostName $HOSTNAME
    User $USER
    IdentityFile $SSH_KEY_FILE
    IdentitiesOnly yes
EOF
        chmod 600 ~/.ssh/config
        log_success "SSH config created"
    else
        log_info "SSH config already exists"
    fi
    
    # Create system SSH key if needed
    if [ ! -f "$SSH_PATH/id_ed25519" ]; then
        ssh-keygen -t ed25519 -C "$USER@$HOSTNAME-system" -f "$SSH_PATH/id_ed25519" -N "" -q > /dev/null 2>&1
        chmod 600 "$SSH_PATH/id_ed25519"
        chmod 644 "$SSH_PATH/id_ed25519.pub"
        
        [ ! -f "$SSH_PATH/authorized_keys" ] && touch "$SSH_PATH/authorized_keys" && chmod 600 "$SSH_PATH/authorized_keys"
        cat "$SSH_PATH/id_ed25519.pub" >> "$SSH_PATH/authorized_keys"
        log_success "System SSH key created"
    fi
    
    # Authenticate with GitHub
    if command -v gh >/dev/null 2>&1; then
        if echo "$GITHUB_TOKEN" | gh auth login --git-protocol ssh --with-token > /dev/null 2>&1; then
            log_success "GitHub authenticated successfully"
            
            # Add SSH key to GitHub
            if [[ -f "${SSH_KEY_FILE}.pub" ]]; then
                if gh ssh-key add "${SSH_KEY_FILE}.pub" --title "${USER}@${HOSTNAME} $(date +%Y-%m-%d)" --type authentication > /dev/null 2>&1; then
                    log_success "SSH key added to GitHub"
                else
                    log_warning "Failed to add SSH key to GitHub (may already exist)"
                fi
            fi
            track_status "GitHub SSH configured & authenticated"
        else
            log_error "GitHub authentication failed"
            track_status "GitHub authentication: FAILED"
        fi
    else
        log_error "GitHub CLI not found"
        track_status "GitHub authentication: FAILED (gh not installed)"
    fi
}


# Pull Authorized Keys from GitHub
pull_authorized_keys() {
    [[ "$PULL_AUTH_KEYS" != "y" ]] || [[ -z "$KEYS_USERNAME" ]] && return
    
    log_info "Pulling authorized_keys from $KEYS_PROVIDER for user: $KEYS_USERNAME..."
    
    # Ensure SSH directory exists
    mkdir -p "$SSH_PATH"
    chmod 700 "$SSH_PATH"
    
    # Create authorized_keys if it doesn't exist
    if [ ! -f "$SSH_PATH/authorized_keys" ]; then
        touch "$SSH_PATH/authorized_keys"
        chmod 600 "$SSH_PATH/authorized_keys"
    fi
    
    # Fetch keys from provider
    KEYS_URL="https://${KEYS_PROVIDER}/${KEYS_USERNAME}.keys"
    TEMP_KEYS=$(mktemp)
    
    if curl -fsSL "$KEYS_URL" -o "$TEMP_KEYS" 2>/dev/null; then
        if [[ -s "$TEMP_KEYS" ]]; then
            # Read existing keys to check for duplicates
            EXISTING_KEYS=$(cat "$SSH_PATH/authorized_keys" 2>/dev/null || echo "")
            
            # Counter for new keys added
            NEW_KEY_COUNT=0
            
            # Add comment header
            echo "" >> "$SSH_PATH/authorized_keys"
            echo "# Keys from $KEYS_PROVIDER/$KEYS_USERNAME (added $(date +%Y-%m-%d))" >> "$SSH_PATH/authorized_keys"
            
            # Process each key
            while IFS= read -r key; do
                # Skip empty lines
                [[ -z "$key" ]] && continue
                
                # Check if key already exists
                if ! echo "$EXISTING_KEYS" | grep -qF "$key"; then
                    echo "$key" >> "$SSH_PATH/authorized_keys"
                    ((NEW_KEY_COUNT++))
                fi
            done < "$TEMP_KEYS"
            
            TOTAL_KEY_COUNT=$(wc -l < "$TEMP_KEYS")
            
            if [[ $NEW_KEY_COUNT -gt 0 ]]; then
                log_success "Added $NEW_KEY_COUNT new SSH key(s) ($TOTAL_KEY_COUNT total found)"
                track_status "Authorized keys imported ($NEW_KEY_COUNT new, $TOTAL_KEY_COUNT total)"
            else
                log_info "No new keys to add (all $TOTAL_KEY_COUNT keys already present)"
                track_status "Authorized keys checked (no new keys)"
            fi
        else
            log_warning "No SSH keys found for $KEYS_PROVIDER user: $KEYS_USERNAME"
            track_status "Authorized keys: No keys found"
        fi
    else
        log_error "Failed to fetch SSH keys from $KEYS_URL"
        track_status "Authorized keys: FAILED"
    fi
    
    # Clean up temp file
    rm -f "$TEMP_KEYS"
}

# System Configuration
configure_system() {
    log_info "Configuring system settings..."
    
    # Disable WiFi rfkill if present
    if [ -f /sys/class/rfkill/rfkill0/soft ]; then
        echo 0 | sudo tee /sys/class/rfkill/rfkill0/soft > /dev/null 2>&1
        echo 0 | sudo tee /sys/class/rfkill/rfkill1/soft > /dev/null 2>&1
        log_success "WiFi rfkill disabled"
    fi
    
    # Disable screen sleep
    LOGIND_CONF="/etc/systemd/logind.conf"
    sudo sed -i 's/^#*HandleLidSwitch=.*/HandleLidSwitch=ignore/' "$LOGIND_CONF"
    sudo sed -i 's/^#*HandleLidSwitchExternalPower=.*/HandleLidSwitchExternalPower=ignore/' "$LOGIND_CONF"
    sudo sed -i 's/^#*HandleLidSwitchDocked=.*/HandleLidSwitchDocked=ignore/' "$LOGIND_CONF"
    log_success "Screen sleep disabled"
    
    # Harden SSH (safely - only disable password auth if keys exist)
    if [[ -f /etc/ssh/sshd_config ]]; then
        # Always disable root login and enable pubkey auth
        sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        
        # Only disable password authentication if SSH keys exist
        if [[ -f "$SSH_PATH/authorized_keys" ]] && [[ -s "$SSH_PATH/authorized_keys" ]]; then
            sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
            log_success "SSH hardened (password authentication disabled)"
        else
            sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
            log_warning "No SSH keys found, keeping password authentication enabled"
        fi
        
        sudo systemctl restart ssh > /dev/null 2>&1 || sudo systemctl restart sshd > /dev/null 2>&1 || true
    fi
    
    # Create user config directories
    mkdir -p "$HOME_DIR/.$USER" "$HOME_DIR/.config"
    if [[ -d "$WORK_DIR" ]]; then
        # Copy alias file if it exists
        if [[ -f "$WORK_DIR/user_configs/alias" ]]; then
            cp "$WORK_DIR/user_configs/alias" "$HOME_DIR/.$USER/" 2>/dev/null
        else
            log_warning "Alias file not found: $WORK_DIR/user_configs/alias"
        fi
        
        # Copy Midnight Commander config if directory exists
        if [[ -d "$WORK_DIR/user_configs/mc/" ]]; then
            cp -r "$WORK_DIR/user_configs/mc/" "$HOME_DIR/.config/" 2>/dev/null
        else
            log_warning "MC config directory not found: $WORK_DIR/user_configs/mc/"
        fi
        
        # Copy scripts if directory exists
        if [[ -d "$WORK_DIR/scripts/" ]]; then
            sudo cp -r "$WORK_DIR/scripts/" "/usr/local/bin/" 2>/dev/null
        else
            log_warning "Scripts directory not found: $WORK_DIR/scripts/"
        fi
        
        log_success "User configuration files copied"
    else
        log_warning "Work directory not found: $WORK_DIR"
    fi
    
    track_status "System configured"
}

# Driver Installation
install_drivers() {
    [[ "$DRIVER_INSTALL" != "y" ]] && return
    
    log_info "Installing drivers and firmware..."
    
    # NVIDIA container toolkit
    log_info "Setting up NVIDIA container toolkit..."
    if curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey 2>/dev/null | \
       sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg 2>/dev/null; then
        curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list 2>/dev/null | \
            sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
            sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list > /dev/null
        
        run_with_spinner "Installing NVIDIA container toolkit..." "sudo apt update > /dev/null 2>&1 && sudo apt install -y nvidia-container-toolkit nvidia-docker2 > /dev/null 2>&1"
        sudo systemctl restart docker > /dev/null 2>&1 || true
        log_success "NVIDIA container toolkit installed"
    fi
    
    # Ubuntu drivers
    # Ubuntu drivers
    if run_with_spinner "Installing Ubuntu drivers..." "sudo apt install -y ubuntu-drivers-common > /dev/null 2>&1 && sudo ubuntu-drivers autoinstall > /dev/null 2>&1"; then
        log_success "Ubuntu drivers installed"
    else
        log_warning "Ubuntu drivers installation completed with warnings"
    fi
    
    # Firmware
    run_with_spinner "Installing firmware packages..." "sudo apt install -y linux-firmware firmware-linux firmware-linux-nonfree intel-microcode amd64-microcode fwupd > /dev/null 2>&1"
    run_with_spinner "Updating firmware..." "sudo fwupdmgr refresh --force > /dev/null 2>&1 && sudo fwupdmgr get-updates > /dev/null 2>&1 && sudo fwupdmgr update -y > /dev/null 2>&1"
    log_success "Firmware updated"
    
    track_status "Drivers & firmware installed"
}

# Desktop Environment Installation
install_desktop() {
    [[ "$DESKTOP_INSTALL" != "y" ]] && return
    
    log_info "Installing XFCE4 desktop environment..."
    if run_with_spinner "Installing XFCE4 and desktop packages..." "sudo apt install -y xfce4 xfce4-goodies lightdm lightdm-gtk-greeter firefox network-manager-gnome pavucontrol xarchiver mousepad thunar-archive-plugin file-roller > /dev/null 2>&1"; then
        sudo systemctl enable lightdm > /dev/null 2>&1 || true
        log_success "XFCE4 desktop environment installed"
        track_status "XFCE4 desktop installed"
    else
        log_error "Failed to install XFCE4"
        track_status "XFCE4 desktop: FAILED"
    fi
}

# Shell Setup (ZSH, Tmux, Powerline)
setup_shell() {
    [[ "$SHELL_SETUP" != "y" ]] && return
    
    log_info "Setting up shell environment..."
    
    # Disable default MOTD
    sudo chmod -x /etc/update-motd.d/* > /dev/null 2>&1 || true
    sudo systemctl disable --now motd-news.service motd-news.timer > /dev/null 2>&1 || true
    echo "ENABLED=0" | sudo tee /etc/default/motd-news > /dev/null 2>&1 || true
    log_success "Default MOTD disabled"
    
    # Create custom MOTD
    sudo tee /usr/local/bin/custom-motd > /dev/null << 'MOTD_SCRIPT'
#!/usr/bin/env bash
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
PINK='\033[1;95m'
DG='\033[1;30m'
RESET='\033[0m'

TERM_WIDTH=$(tput cols 2>/dev/null || echo 80)

center_text() {
    local text="$1"
    local width=$(echo -e "$text" | sed 's/\x1b\[[0-9;]*m//g' | wc -L)
    local padding=$(( (TERM_WIDTH - width) / 2 ))
    [ $padding -lt 0 ] && padding=0
    printf "%${padding}s" ""
    echo -e "$text"
}

echo -e "${BLUE}"
figlet -c -w "$TERM_WIDTH" "$(hostname)"
echo -e "${RESET}"

COWSAY_OUTPUT=$(cowsay -W $((TERM_WIDTH - 20)) "welcome back, $(whoami)")
echo -e "${PINK}"
while IFS= read -r line; do center_text "$line"; done <<< "$COWSAY_OUTPUT"
echo -e "${RESET}"
echo

get_cpu_usage() { top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}'; }
get_memory_usage() { free -m | awk 'NR==2{printf "%.1f/%.1fGB", $3/1024, $2/1024}'; }
get_memory_percent() { free | awk 'NR==2{printf "%.0f", $3*100/$2}'; }
get_battery() {
    [ -d /sys/class/power_supply/BAT0 ] && cat /sys/class/power_supply/BAT0/capacity 2>/dev/null || \
    [ -d /sys/class/power_supply/BAT1 ] && cat /sys/class/power_supply/BAT1/capacity 2>/dev/null || echo ""
}
get_uptime() { uptime -p | sed 's/up //'; }

CPU=$(get_cpu_usage)
MEM=$(get_memory_usage)
MEM_PCT=$(get_memory_percent)
BAT=$(get_battery)
UPTIME=$(get_uptime)

CPU_COLOR=$GREEN
(( $(echo "$CPU > 50" | bc -l) )) && CPU_COLOR=$YELLOW
(( $(echo "$CPU > 80" | bc -l) )) && CPU_COLOR=$RED

MEM_COLOR=$GREEN
(( $MEM_PCT > 60 )) && MEM_COLOR=$YELLOW
(( $MEM_PCT > 80 )) && MEM_COLOR=$RED

if [ -n "$BAT" ]; then
    BAT_COLOR=$GREEN
    (( $BAT < 50 )) && BAT_COLOR=$YELLOW
    (( $BAT < 20 )) && BAT_COLOR=$RED
    STATS_LINE=" ${CPU_COLOR}cpu ${CPU}%%${RESET} ${DG}|${RESET} ${MEM_COLOR}mem ${MEM}${RESET} ${DG}|${RESET} ${BAT_COLOR}bat ${BAT}%%${RESET} ${DG}|${RESET} ${CYAN}uptime: ${UPTIME}${RESET} "
    PLAIN_LINE=" cpu ${CPU}% | mem ${MEM} | bat ${BAT}% | uptime: ${UPTIME} "
else
    STATS_LINE=" ${CPU_COLOR}cpu ${CPU}%%${RESET} ${DG}|${RESET} ${MEM_COLOR}mem ${MEM}${RESET} ${DG}|${RESET} ${CYAN}uptime: ${UPTIME}${RESET} "
    PLAIN_LINE=" cpu ${CPU}% | mem ${MEM} | uptime: ${UPTIME} "
fi

LINE_LENGTH=${#PLAIN_LINE}
BAR_WIDTH=$((LINE_LENGTH + 2))

center_text "${DG}┌$(printf '─%.0s' $(seq 1 $BAR_WIDTH))┐${RESET}"
center_text "${DG}│${RESET}${STATS_LINE}${DG}│${RESET}"
center_text "${DG}└$(printf '─%.0s' $(seq 1 $BAR_WIDTH))┘${RESET}"
echo
MOTD_SCRIPT
    sudo chmod +x /usr/local/bin/custom-motd
    log_success "Custom MOTD created"
    
    # Setup Tmux
    if run_with_spinner "Installing xclip..." "command -v xclip &> /dev/null || sudo apt install -y xclip > /dev/null 2>&1"; then
        [ -f ~/.tmux.conf ] && cp ~/.tmux.conf ~/.tmux.conf.backup.$(date +%Y%m%d_%H%M%S)
        
        cat > ~/.tmux.conf << 'EOF'
unbind C-b
set -g prefix C-s
bind C-s send-prefix

set -g mouse on
set -g default-terminal "tmux-256color"
set -ga terminal-overrides ",xterm-256color:Tc"

set -g status on
set -g status-bg black
set -g status-fg white
set -g status-interval 1
set -g status-left-length 100
set -g status-left "#(tmux list-sessions | awk 'BEGIN{ORS=\"\"} {gsub(/:.*/, \"\", $1); if ($0 ~ /attached/) print \"#[fg=black,bg=pink,bold] [\" $1 \"] #[bg=black]\"; else print \"#[fg=gray] [\" $1 \"] \"}')"
set -g status-right-length 60
set -g status-right "#[fg=cyan]#(whoami)#[fg=white]@#[fg=green]#h #[fg=pink]| #[fg=white]%Y-%m-%d %H:%M"
set -g status-justify centre

setw -g window-status-format "#[fg=gray] #I:#W "
setw -g window-status-current-format "#[fg=pink,bold] #I:#W "

bind | split-window -h
bind - split-window -v

setw -g mode-keys vi
bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "xclip -selection clipboard -in"
bind-key y run-shell "tmux save-buffer - | xclip -selection clipboard"

bind r source-file ~/.tmux.conf \; display-message "config reloaded"

bind Space run-shell "tmux split-window -h \; tmux select-pane -t 0 \; tmux split-window -v \; tmux select-pane -t 2 \; tmux split-window -v"
bind m run-shell "SESSION_NAME=\"session-$(date +%s)\"; tmux new-session -d -s \"\$SESSION_NAME\" \; tmux split-window -h -t \"\$SESSION_NAME\" \; tmux select-pane -t 0 \; tmux split-window -v \; tmux select-pane -t 2 \; tmux split-window -v \; tmux select-pane -t 0 \; tmux switch-client -t \"\$SESSION_NAME\""
bind M command-prompt -p "new session name:" "new-session -d -s '%%' \; split-window -h -t '%%' \; select-pane -t 0 \; split-window -v \; select-pane -t 2 \; split-window -v \; select-pane -t 0 \; switch-client -t '%%'"
EOF
        tmux info &> /dev/null 2>&1 && tmux source-file ~/.tmux.conf > /dev/null 2>&1
        log_success "Tmux configured"
    fi
    
    # Setup Vim & Powerline
    run_with_spinner "Installing Powerline..." "command -v pipx &> /dev/null || { sudo apt install -y pipx > /dev/null 2>&1 && pipx ensurepath > /dev/null 2>&1; }; pipx list 2>/dev/null | grep -q powerline-status || pipx install powerline-status > /dev/null 2>&1"
    
    # Copy Vim config if it exists
    if [[ -f "$THEME_CONFIGS_DIR/.vimrc" ]]; then
        cp "$THEME_CONFIGS_DIR/.vimrc" ~/.vimrc
    else
        log_warning "Vim config not found: $THEME_CONFIGS_DIR/.vimrc"
    fi
    
    sudo apt install -y fonts-powerline > /dev/null 2>&1
    
    # Copy custom fonts if directory exists
    if [[ -d "$FONTS_DIR" ]]; then
        mkdir -p ~/.fonts
        cp -a "$FONTS_DIR"/. ~/.fonts/
        fc-cache -vf ~/.fonts/ > /dev/null 2>&1
    else
        log_warning "Fonts directory not found: $FONTS_DIR"
    fi
    
    log_success "Vim & Powerline configured"
    
    # Setup ZSH
    run_with_spinner "Installing ZSH..." "sudo apt install -y git-core zsh curl > /dev/null 2>&1"
    
    if [ ! -d ~/.oh-my-zsh ]; then
        run_with_spinner "Installing Oh-My-Zsh..." "RUNZSH=no sh -c \"\$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)\" > /dev/null 2>&1"
    fi
    
    [ ! -d ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting ] && \
        run_with_spinner "Installing ZSH syntax highlighting..." "(cd ~/.oh-my-zsh/custom/plugins && git clone https://github.com/zsh-users/zsh-syntax-highlighting > /dev/null 2>&1)"
    
    [ ! -d ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions ] && \
        run_with_spinner "Installing ZSH autosuggestions..." "(cd ~/.oh-my-zsh/custom/plugins && git clone https://github.com/zsh-users/zsh-autosuggestions > /dev/null 2>&1)"
    
    # Copy ZSH config files if they exist
    if [[ -f "$THEME_CONFIGS_DIR/.zshrc" ]]; then
        cp "$THEME_CONFIGS_DIR/.zshrc" ~/.zshrc
    else
        log_warning "ZSH config not found: $THEME_CONFIGS_DIR/.zshrc"
    fi

    if [[ -f "$THEME_CONFIGS_DIR/pixegami-agnoster.zsh-theme" ]]; then
        mkdir -p ~/.oh-my-zsh/themes/
        cp "$THEME_CONFIGS_DIR/pixegami-agnoster.zsh-theme" ~/.oh-my-zsh/themes/
    else
        log_warning "ZSH theme not found: $THEME_CONFIGS_DIR/pixegami-agnoster.zsh-theme"
    fi
    
    # Change default shell to ZSH with proper error handling
    log_info "Changing default shell to ZSH..."
    ZSH_PATH=$(which zsh 2>/dev/null)
    if [[ -n "$ZSH_PATH" ]]; then
        if command -v sudo >/dev/null 2>&1 && [[ $EUID -ne 0 ]]; then
            if sudo chsh -s "$ZSH_PATH" "$USER" 2>/dev/null; then
                log_success "Default shell changed to ZSH (using sudo)"
            else
                log_warning "Failed to change shell with sudo. Please run 'chsh -s $(which zsh)' manually."
            fi
        else
            if chsh -s "$ZSH_PATH" 2>/dev/null; then
                log_success "Default shell changed to ZSH"
            else
                log_warning "Failed to change shell. Please run 'chsh -s $(which zsh)' manually."
            fi
        fi
    else
        log_error "ZSH not found in PATH, cannot change shell"
    fi
    
    track_status "Shell environment configured"
}

# Configure Rclone
setup_rclone() {
    [[ "$PASTE_RCLONE" != "y" ]] && return
    
    log_info "Configuring rclone..."
    
    # Create rclone directory if it doesn't exist
    mkdir -p "$RCLONE_DIR"
    
    # Backup existing config if present
    if [[ -f "$RCLONE_CONF" ]]; then
        cp "$RCLONE_CONF" "$RCLONE_BAK"
        log_success "Existing rclone config backed up"
    fi
    
    # Write the pasted content to config file
    echo "$RCLONE_CONTENT" > "$RCLONE_CONF"
    chmod 600 "$RCLONE_CONF"
    log_success "Rclone config saved to $RCLONE_CONF"
    
    track_status "Rclone configured"
}

# Final System Updates
final_updates() {
    log_info "Performing final system updates..."
    run_with_spinner "Updating package lists..." "sudo apt update > /dev/null 2>&1"
    run_with_spinner "Upgrading packages..." "sudo apt upgrade -y > /dev/null 2>&1"
    run_with_spinner "Removing unused packages..." "sudo apt autoremove -y > /dev/null 2>&1"
    run_with_spinner "Cleaning package cache..." "sudo apt autoclean > /dev/null 2>&1"
    log_success "System fully updated"
    track_status "Final updates completed"
}

# Status Summary
show_status_summary() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Setup Complete!${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    
    echo -e "${GREEN}Installation Status:${NC}"
    for status in "${INSTALL_STATUS[@]}"; do
        if [[ "$status" == *"FAILED"* ]]; then
            echo -e "  ${RED}✗${NC} $status"
        else
            echo -e "  ${GREEN}✓${NC} $status"
        fi
    done
    echo
    
    echo -e "${CYAN}Important Notes:${NC}"
    [[ "$DOCKER_INSTALL" == "y" ]] && echo -e "  ${YELLOW}•${NC} Docker group added - requires logout/login to take effect"
    [[ "$SHELL_SETUP" == "y" ]] && echo -e "  ${YELLOW}•${NC} ZSH is now default shell - changes take effect after reboot"
    [[ "$CONFIGURE_GIT" == "y" ]] && echo -e "  ${YELLOW}•${NC} Git configured with username and email"
    [[ "$SETUP_GITHUB" == "y" ]] && [[ "$GITHUB_METHOD" == "y" ]] && echo -e "  ${YELLOW}•${NC} GitHub SSH key configured - check GitHub settings"
    [[ "$PULL_AUTH_KEYS" == "y" ]] && echo -e "  ${YELLOW}•${NC} SSH keys imported to $SSH_PATH/authorized_keys"
    [[ "$PASTE_RCLONE" == "y" ]] && echo -e "  ${YELLOW}•${NC} Rclone config saved to $RCLONE_CONF"
    [[ "$DESKTOP_INSTALL" == "y" ]] && echo -e "  ${YELLOW}•${NC} XFCE4 desktop will be available after reboot"
    [[ "$DRIVER_INSTALL" == "y" ]] && echo -e "  ${YELLOW}•${NC} Drivers installed - reboot recommended"
    echo
    
    echo -e "${BLUE}========================================${NC}"
    echo
}

# Argument parsing
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "initium v2.1.0"
                exit 0
                ;;
            --backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --config-dir)
                CONFIG_DIR="$2"
                shift 2
                ;;
            --log-file)
                LOG_FILE="$2"
                shift 2
                ;;
            *)
                log_warning "Unknown option: $1"
                shift
                ;;
        esac
    done
}

# Main Execution Flow
main() {
    # Parse command line arguments
    parse_args "$@"
    
    # Collect configuration
    collect_configuration
    
    # Show summary and confirm
    show_configuration_summary
    
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Starting Installation...${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    
    # Execute installations in order
    update_base_system
    install_packages
    install_docker
    install_nodejs
    configure_git
    setup_github_auth
    pull_authorized_keys
    configure_system
    install_drivers
    install_desktop
    setup_shell
    setup_rclone
    final_updates
    
    # Show final status
    show_status_summary
    
    # Prompt for reboot
    REBOOT_NOW=$(get_yn "Reboot now to complete setup?")
    if [[ "$REBOOT_NOW" == "y" ]]; then
        echo
        log_info "Rebooting in 5 seconds..."
        sleep 5
        sudo reboot
    else
        echo
        log_warning "Reboot skipped - please reboot manually to complete setup"
        echo
    fi
}

# Script Entry Point
main "$@"
