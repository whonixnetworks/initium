#!/usr/bin/env bash
# initium — Ubuntu system setup and configuration script
# author: greedy
# version: 2.4.2

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
    show_header "Initium v2.4.2"

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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THEME_CONFIGS_DIR="$SCRIPT_DIR/theme/configs"
FONTS_DIR="$SCRIPT_DIR/theme/fonts"
USER_CONFIGS_DIR="$SCRIPT_DIR/user_configs"
SSH_PATH="$HOME_DIR/.ssh"
HOSTNAME=$(hostname)

INSTALL_STATUS=()

# spinner function
spinner() {
    local pid=$1
    local message=$2
    local spinstr='|/-\'
    local temp
    
    tput civis
    
    while kill -0 "$pid" 2>/dev/null; do
        temp=${spinstr#?}
        printf " ${BLUE}[%c]${NC} %s\r" "$spinstr" "$message"
        spinstr=$temp${spinstr%"$temp"}
        sleep 0.1
    done
    tput cnorm
    printf "\r\033[K"
    wait "$pid"
    return $?
}

run_with_spinner() {
    local message=$1
    shift
    local cmd="$@"
    eval "$cmd" &
    local pid=$!
    spinner "$pid" "$message"
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

    # System configuration
    echo -e "${MAGENTA}=== System Configuration ===${NC}"
    DRIVER_INSTALL=$(get_yn "Install drivers & firmware?")
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

    echo -e "${CYAN}System Configuration:${NC}"
    [[ "$DRIVER_INSTALL" == "y" ]] && echo -e "  ${GREEN}✓${NC} Drivers & firmware" || echo -e "  ${GRAY}✗${NC} Drivers & firmware"
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
    if run_with_spinner "Installing development tools and utilities..." "sudo apt install -y dconf-cli htop gh locate fzf ansiweather wireguard cowsay wireguard-tools bc tmux snapd iotop iftop coreutils rsync figlet p7zip-full wipe lolcat python3-full python3-pip speedtest-cli > /dev/null 2>&1"; then
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
        local ssh_auth_keys="${SSH_PATH:-$HOME_DIR/.ssh}/authorized_keys"
        if [[ -f "$ssh_auth_keys" ]] && [[ -s "$ssh_auth_keys" ]]; then
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
    if [[ -d "$USER_CONFIGS_DIR" ]]; then
        # Copy alias file if it exists
        if [[ -f "$USER_CONFIGS_DIR/alias" ]]; then
            cp "$USER_CONFIGS_DIR/alias" "$HOME_DIR/.$USER/" 2>/dev/null
        else
            log_warning "Alias file not found: $USER_CONFIGS_DIR/alias"
        fi
        
        # Copy Midnight Commander config if directory exists
        if [[ -d "$USER_CONFIGS_DIR/mc/" ]]; then
            cp -r "$USER_CONFIGS_DIR/mc/" "$HOME_DIR/.config/" 2>/dev/null
        else
            log_warning "MC config directory not found: $USER_CONFIGS_DIR/mc/"
        fi
        
        log_success "User configuration files copied"
    else
        log_warning "User configs directory not found: $USER_CONFIGS_DIR"
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
        tmux info &> /dev/null && tmux source-file ~/.tmux.conf > /dev/null 2>&1
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
                echo "initium v2.4.2"
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
    configure_system
    install_drivers
    setup_shell
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
