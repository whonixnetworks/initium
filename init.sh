#!/usr/bin/env bash

# System Configuration TUI Script
# A whiptail-based menu system for common system administration tasks

set -euo pipefail

BLUE="\033[34m"
YELLOW="\033[33m"
RED="\033[31m"
GREEN="\033[32m"
RESET="\033[0m"

# spinner function
spinner() {
   local pid=$1 delay=0.1 spinstr='|/-\'
   while kill -0 "$pid" 2>/dev/null; do
       local temp=${spinstr#?}
       printf " [%c]  " "$spinstr"
       spinstr=$temp${spinstr%"$temp"}
       sleep $delay
       printf "\b\b\b\b\b\b"
   done
   printf "    \b\b\b\b"
}

# Get terminal dimensions
get_terminal_size() {
    TERM_WIDTH=$(tput cols)
    TERM_HEIGHT=$(tput lines)
    
    # Set default minimum sizes
    if [ "$TERM_WIDTH" -lt 60 ]; then
        TERM_WIDTH=60
    else
        # Cap maximum width for better readability
        if [ "$TERM_WIDTH" -gt 120 ]; then
            TERM_WIDTH=120
        fi
    fi
    if [ "$TERM_HEIGHT" -lt 20 ]; then
        TERM_HEIGHT=20
    else
        # Cap maximum height
        if [ "$TERM_HEIGHT" -gt 40 ]; then
            TERM_HEIGHT=40
        fi
    fi
    
    # Calculate responsive dimensions
    MENU_HEIGHT=$((TERM_HEIGHT - 8))
    if [ "$MENU_HEIGHT" -lt 10 ]; then
        MENU_HEIGHT=10
    fi
    MSGBOX_HEIGHT=$((TERM_HEIGHT / 2))
    if [ "$MSGBOX_HEIGHT" -lt 8 ]; then
        MSGBOX_HEIGHT=8
    fi
    GAUGE_HEIGHT=8
    if [ "$TERM_HEIGHT" -lt 25 ]; then
        GAUGE_HEIGHT=6
    fi
}

# user check
check_root() {
   get_terminal_size
   if [ "$EUID" -eq 0 ]; then
       whiptail --title "Warning" --msgbox "Please do not run this script as root. Run as a regular user with sudo privileges." $MSGBOX_HEIGHT $TERM_WIDTH
       exit 1
   fi
}

# verify sudo
verify_sudo() {
   get_terminal_size
   if ! sudo -v; then
       whiptail --title "Error" --msgbox "Failed to obtain sudo privileges. Exiting." $MSGBOX_HEIGHT $TERM_WIDTH
       exit 1
   fi
}

# determine shell (zsh/bash)
# copy alias file
add_alias() {
    # 1. Determine the shell: check for shell-specific variables
    local SHELL_RC_FILE
    if [[ -n "${ZSH_VERSION:-}" ]]; then
        SHELL_RC_FILE="$HOME/.zshrc"
    elif [[ -n "${BASH_VERSION:-}" ]]; then
        SHELL_RC_FILE="$HOME/.bashrc"
    else
        echo "Error: Could not determine if current shell is Bash or Zsh." >&2
        return 1
    fi

    # 2. Check if the file "alias" exists in the current directory
    local ALIAS_FILE_NAME="alias"
    local DEST_ALIAS_FILE="$HOME/.alias"
    local ALIAS_SOURCE_LINE="[ -f $DEST_ALIAS_FILE ] && source $DEST_ALIAS_FILE"

    if [[ ! -f "$ALIAS_FILE_NAME" ]]; then
        echo "Error: 'alias' file not found in the current directory." >&2
        return 1
    fi

    # 3. Copy the alias file to ~/.alias
    if ! cp "$ALIAS_FILE_NAME" "$DEST_ALIAS_FILE"; then
        echo "Error: Failed to copy '$ALIAS_FILE_NAME' to '$DEST_ALIAS_FILE'." >&2
        return 1
    fi

    # 4. Add the source line to the shell's RC file if it's not already there
    if ! grep -qF "$ALIAS_SOURCE_LINE" "$SHELL_RC_FILE" 2>/dev/null; then
        echo -e "\n# Source external aliases file" >> "$SHELL_RC_FILE"
        echo "$ALIAS_SOURCE_LINE" >> "$SHELL_RC_FILE"
    fi

    # 5. Return RC file path on success
    echo "$SHELL_RC_FILE"
    return 0
}


# system update
system_update() {
   get_terminal_size
   if whiptail --title "System Updates" --yesno "This will update and upgrade all system packages.\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "10" ; sleep 0.5
           sudo apt-get update >/dev/null 2>&1
           echo "50" ; sleep 0.5
           sudo apt-get upgrade -y >/dev/null 2>&1
           echo "90" ; sleep 0.5
           sudo apt-get autoremove -y >/dev/null 2>&1
           echo "100" ; sleep 0.5
       } | whiptail --title "System Updates" --gauge "Updating system packages..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "System updates completed successfully!" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# --- Installation Logic Functions ---
# These functions do the work without any UI, so they can be reused.

_install_base_logic() {
   sudo apt install -y locate fzf gh ansiweather btop wireguard wireguard-tools bc unattended-upgrades software-properties-common tmux snapd neofetch mc htop iotop iftop wget curl jq nano git coreutils rclone rsync figlet p7zip-full wipe ufw openssh-server ipcalc >/dev/null 2>&1
}

_install_docker_logic_apt() {
   sudo apt install -y docker.io docker-compose-v2 >/dev/null 2>&1
}

_install_docker_logic_systemctl() {
   sudo systemctl enable docker >/dev/null 2>&1
   sudo systemctl start docker >/dev/null 2>&1
}

_install_docker_logic_usermod() {
   sudo usermod -aG docker "$(whoami)"
}

_install_dev_logic() {
   sudo apt install -y python3 python3-pip speedtest-cli>/dev/null 2>&1
}

# --- Installation UI Functions ---

# install base packs
install_base() {
   get_terminal_size
   if whiptail --title "Install Base Packages" --yesno "This will install base packs like: git, gh, nano\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "33" ; sleep 0.5
           _install_base_logic
           echo "100" ; sleep 0.5
       } | whiptail --title "Installing" --gauge "Installing base packages..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "Base packages installed successfully!" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# install docker
install_docker() {
   get_terminal_size
   if whiptail --title "Install Docker" --yesno "This will install Docker and Docker Compose, and add your user to the docker group.\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "20" ; sleep 0.5
           _install_docker_logic_apt
           echo "60" ; sleep 0.5
           _install_docker_logic_systemctl
           echo "80" ; sleep 0.5
           _install_docker_logic_usermod
           echo "100" ; sleep 0.5
       } | whiptail --title "Installing" --gauge "Installing Docker..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "Docker installed successfully!\n\nNote: You need to log out and back in for group membership to take effect." $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# install dev packs
install_dev() {
   get_terminal_size
   if whiptail --title "Install Dev Packages" --yesno "This will install: python3, pip, npm and more\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "33" ; sleep 0.5
           _install_dev_logic
           echo "100" ; sleep 0.5
       } | whiptail --title "Installing" --gauge "Installing development packages..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "Development packages installed successfully!" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# Install all packages
install_all() {
   get_terminal_size
   if whiptail --title "Install All Packages" --yesno "This will install:\n- Base Packages\n- Docker\n- Dev Packages\n\nThis may take several minutes.\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "0"
           echo "XXX"
           echo "Starting install..."
           echo "XXX"
           sleep 1

           echo "10"
           echo "XXX"
           echo "Installing Base Packages..."
           echo "XXX"
           _install_base_logic
           
           echo "40"
           echo "XXX"
           echo "Installing Docker..."
           echo "XXX"
           _install_docker_logic_apt
           
           echo "60"
           echo "XXX"
           echo "Configuring Docker..."
           echo "XXX"
           _install_docker_logic_systemctl
           
           echo "70"
           echo "XXX"
           echo "Adding user to Docker group..."
           echo "XXX"
           _install_docker_logic_usermod

           echo "85"
           echo "XXX"
           echo "Installing Dev Packages..."
           echo "XXX"
           _install_dev_logic

           echo "100"
           echo "XXX"
           echo "All packages installed!"
           echo "XXX"
           sleep 1
       } | whiptail --title "Installing All Packages" --gauge "Please wait..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "All packages (Base, Docker, Dev) installed successfully!\n\nNote: You need to log out and back in for Docker group membership to take effect." $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# Install Packages Submenu
install_packages_menu() {
   get_terminal_size
   while true; do
       CHOICE=$(whiptail --title "Install Packages" --menu "Choose an option:" $MENU_HEIGHT $TERM_WIDTH 6 \
           "1" "Install Base Packages" \
           "2" "Install Docker" \
           "3" "Install Dev Packages" \
           "4" "Install ALL (Base, Docker, Dev)" \
           "5" "Back to Main Menu" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) install_base ;;
           2) install_docker ;;
           3) install_dev ;;
           4) install_all ;;
           5) break ;;
       esac
   done
}

# create MOTD
create_motd() {
   get_terminal_size
   local hostname_display
   hostname_display=$(hostname)

   # Check if figlet is installed
   if ! command -v figlet &>/dev/null; then
       if whiptail --title "Install Figlet" --yesno "Figlet is required to create MOTD.\n\nDo you want to install it?" $MSGBOX_HEIGHT $TERM_WIDTH; then
           {
               echo "50" ; sleep 0.5
               sudo apt install -y figlet >/dev/null 2>&1
               echo "100" ; sleep 0.5
           } | whiptail --title "Installing" --gauge "Installing figlet..." $GAUGE_HEIGHT $TERM_WIDTH 0
       else
           return
       fi
   fi

   # Get custom text for MOTD
   MOTD_TEXT=$(whiptail --title "Create MOTD" --inputbox "Enter text for MOTD (or leave blank for hostname):" 10 60 "$hostname_display" 3>&1 1>&2 2>&3)

   if [ -z "$MOTD_TEXT" ]; then
       MOTD_TEXT="$hostname_display"
   fi

   {
       echo "20" ; sleep 0.5
       # Disable dynamic MOTD scripts
       sudo chmod -x /etc/update-motd.d/* 2>/dev/null || true
       echo "40" ; sleep 0.5
       # Disable motd-news
       sudo systemctl disable --now motd-news.service motd-news.timer 2>/dev/null || true
       echo "ENABLED=0" | sudo tee /etc/default/motd-news >/dev/null 2>&1 || true
       echo "60" ; sleep 0.5
       # Create the MOTD
       figlet "$MOTD_TEXT" | sudo tee /etc/motd >/dev/null
       echo "100" ; sleep 0.5
   } | whiptail --title "Creating MOTD" --gauge "Creating MOTD..." $GAUGE_HEIGHT $TERM_WIDTH 0

   # Show preview
   PREVIEW=$(cat /etc/motd)
   whiptail --title "MOTD Created" --msgbox "MOTD has been created:\n\n$PREVIEW" $MSGBOX_HEIGHT $TERM_WIDTH
}

# --- System Settings Functions ---

# change hostname
change_hostname() {
   get_terminal_size
   CURRENT_HOSTNAME=$(hostname)
   NEW_HOSTNAME=$(whiptail --title "Change Hostname" --inputbox "Enter new hostname:\n\nCurrent: $CURRENT_HOSTNAME" 12 60 3>&1 1>&2 2>&3)

   if [ -z "$NEW_HOSTNAME" ]; then
       return
   fi

   if ! [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
       whiptail --title "Error" --msgbox "Invalid hostname format.\nUse only letters, numbers, and hyphens." $MSGBOX_HEIGHT $TERM_WIDTH
       return
   fi

   {
       echo "50" ; sleep 0.5
       sudo hostnamectl set-hostname "$NEW_HOSTNAME"
       sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
       echo "100" ; sleep 0.5
   } | whiptail --title "Changing Hostname" --gauge "Setting hostname to $NEW_HOSTNAME..." $GAUGE_HEIGHT $TERM_WIDTH 0

   whiptail --title "Success" --msgbox "Hostname changed to: $NEW_HOSTNAME\n\nPlease reboot for all changes to take effect." $MSGBOX_HEIGHT $TERM_WIDTH
}

# view system usage
view_system_usage() {
   get_terminal_size
   CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{printf "%.1f", 100 - $1}')
   MEM_INFO=$(free -h | grep Mem)
   MEM_TOTAL=$(echo $MEM_INFO | awk '{print $2}')
   MEM_USED=$(echo $MEM_INFO | awk '{print $3}')
   DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}')
   UPTIME=$(uptime -p)

   whiptail --title "System Usage" --msgbox "CPU Usage: ${CPU_USAGE}%\n\nMemory: $MEM_USED / $MEM_TOTAL\n\nDisk Usage: $DISK_USAGE\n\nUptime: $UPTIME" $MSGBOX_HEIGHT $TERM_WIDTH
}

# harden SSH
harden_ssh() {
   get_terminal_size
   if ! whiptail --title "Harden SSH" --yesno "WARNING: This will:\n- Disable password authentication\n- Disable root login with password\n- Require SSH keys for authentication\n\nEnsure you have SSH keys set up!\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       return
   fi

   {
       echo "25" ; sleep 0.5
       sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
       echo "50" ; sleep 0.5
       sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
       sudo sed -i 's/^#\?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
       sudo sed -i 's/^#\?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
       sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
       echo "75" ; sleep 0.5
       sudo systemctl reload ssh
       echo "100" ; sleep 0.5
   } | whiptail --title "Hardening SSH" --gauge "Configuring SSH..." $GAUGE_HEIGHT $TERM_WIDTH 0

   whiptail --title "Success" --msgbox "SSH has been hardened.\n\nBackup saved to: /etc/ssh/sshd_config.bak\n\nPassword login is now DISABLED." $MSGBOX_HEIGHT $TERM_WIDTH
}

# configure UFW
configure_ufw() {
   get_terminal_size
   if ! command -v ufw &>/dev/null; then
       if whiptail --title "Install UFW" --yesno "UFW is not installed.\n\nDo you want to install it?" $MSGBOX_HEIGHT $TERM_WIDTH; then
           {
               echo "50" ; sleep 0.5
               sudo apt install -y ufw >/dev/null 2>&1
               echo "100" ; sleep 0.5
           } | whiptail --title "Installing" --gauge "Installing UFW..." $GAUGE_HEIGHT $TERM_WIDTH 0
       else
           return
       fi
   fi

   CHOICE=$(whiptail --title "Configure UFW" --menu "Choose an option:" $MENU_HEIGHT $TERM_WIDTH 5 \
       "1" "Enable UFW" \
       "2" "Allow SSH (port 22)" \
       "3" "Apply UFW Defaults" \
       "4" "Check UFW Status" \
       "5" "Back" 3>&1 1>&2 2>&3)

   case $CHOICE in
       1)
           {
               echo "50" ; sleep 0.5
               sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw 2>/dev/null || true
               sudo ufw --force enable >/dev/null 2>&1
               echo "100" ; sleep 0.5
           } | whiptail --title "Enabling UFW" --gauge "Enabling firewall..." $GAUGE_HEIGHT $TERM_WIDTH 0
           whiptail --title "Success" --msgbox "UFW has been enabled." $MSGBOX_HEIGHT $TERM_WIDTH
           ;;
       2)
           sudo ufw allow 22/tcp >/dev/null 2>&1
           whiptail --title "Success" --msgbox "SSH (port 22) has been allowed through the firewall." $MSGBOX_HEIGHT $TERM_WIDTH
           ;;
       3)
           if whiptail --title "UFW Defaults" --yesno "This will set UFW defaults to:\n- Deny incoming\n- Allow outgoing\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
               {
                   echo "50" ; sleep 0.5
                   sudo ufw default deny incoming
                   sudo ufw default allow outgoing
                   echo "100" ; sleep 0.5
               } | whiptail --title "Applying Defaults" --gauge "Setting UFW defaults..." $GAUGE_HEIGHT $TERM_WIDTH 0
               whiptail --title "Success" --msgbox "UFW defaults applied: deny incoming, allow outgoing." $MSGBOX_HEIGHT $TERM_WIDTH
           fi
           ;;
       4)
           STATUS=$(sudo ufw status verbose)
           whiptail --title "UFW Status" --msgbox "$STATUS" $MSGBOX_HEIGHT $TERM_WIDTH --scrolltext
           ;;
       5)
           return
           ;;
   esac
}

# NEW: Add new user
add_new_user() {
   get_terminal_size
   NEW_USER=$(whiptail --title "Add New User" --inputbox "Enter username for the new user:" 10 60 3>&1 1>&2 2>&3)
   
   if [ -z "$NEW_USER" ]; then
       return
   fi
   
   PASSWORD=$(whiptail --title "Set Password" --passwordbox "Enter password for $NEW_USER:" 10 60 3>&1 1>&2 2>&3)
   
   if [ -z "$PASSWORD" ]; then
       whiptail --title "Error" --msgbox "Password cannot be empty." $MSGBOX_HEIGHT $TERM_WIDTH
       return
   fi

   PASSWORD_CONFIRM=$(whiptail --title "Confirm Password" --passwordbox "Confirm password:" 10 60 3>&1 1>&2 2>&3)

   if [ "$PASSWORD" != "$PASSWORD_CONFIRM" ]; then
       whiptail --title "Error" --msgbox "Passwords do not match." $MSGBOX_HEIGHT $TERM_WIDTH
       return
   fi

   {
       echo "30" ; sleep 0.5
       sudo useradd -m -s /bin/bash "$NEW_USER"
       echo "60" ; sleep 0.5
       echo "$NEW_USER:$PASSWORD" | sudo chpasswd
       echo "100" ; sleep 0.5
   } | whiptail --title "Creating User" --gauge "Creating user $NEW_USER..." $GAUGE_HEIGHT $TERM_WIDTH 0
   
   whiptail --title "Success" --msgbox "User '$NEW_USER' created successfully." $MSGBOX_HEIGHT $TERM_WIDTH

   if whiptail --title "Add Sudo Privileges" --yesno "Do you want to add '$NEW_USER' to the 'sudo' group?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       sudo usermod -aG sudo "$NEW_USER"
       whiptail --title "Success" --msgbox "User '$NEW_USER' has been added to the 'sudo' group." $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# NEW: Manage SSH Keys
manage_ssh_keys() {
    get_terminal_size
    CHOICE=$(whiptail --title "Manage SSH Keys" --menu "Choose an option:" $MENU_HEIGHT $TERM_WIDTH 5 \
        "1" "Add Public Key from URL (e.g., GitHub)" \
        "2" "Generate New SSH Key Pair" \
        "3" "Add Local id_rsa.pub to authorized_keys" \
        "4" "Paste Public Key Manually" \
        "5" "Back to System Settings" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
        return
    fi

    case $CHOICE in
        1) # Add from URL
            KEY_URL=$(whiptail --title "Add Key from URL" --inputbox "Enter the URL to fetch the public key from:\n(e.g., https://github.com/username.keys)" 10 60 "https://github.com/" 3>&1 1>&2 2>&3)
            if [ -z "$KEY_URL" ]; then
                return
            fi

            if ! whiptail --title "Confirm" --yesno "This will fetch keys from:\n$KEY_URL\n\nIf ~/.ssh/authorized_keys exists, it will be backed up to ~/.ssh/oldkeys.\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
                return
            fi

            {
                echo "10" ; sleep 0.5
                mkdir -p ~/.ssh
                chmod 700 ~/.ssh
                echo "30" ; sleep 0.5
                if [ -f ~/.ssh/authorized_keys ]; then
                    mv ~/.ssh/authorized_keys ~/.ssh/oldkeys
                fi
                echo "60" ; sleep 0.5
                curl -s "$KEY_URL" >> ~/.ssh/authorized_keys
                echo "90" ; sleep 0.5
                chmod 600 ~/.ssh/authorized_keys
                echo "100" ; sleep 0.5
            } | whiptail --title "Fetching Keys" --gauge "Downloading and saving keys..." $GAUGE_HEIGHT $TERM_WIDTH 0
            whiptail --title "Success" --msgbox "Keys from $KEY_URL added to ~/.ssh/authorized_keys." $MSGBOX_HEIGHT $TERM_WIDTH
            ;;
        2) # Generate new keys
            if whiptail --title "Generate SSH Keys" --yesno "This will run 'ssh-keygen' to create a new SSH key pair.\n\nYou will be prompted for a file location and an optional passphrase.\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
                ssh-keygen -t rsa -b 4096
                whiptail --title "Success" --msgbox "SSH key generation process finished.\n\nYour public key is likely at ~/.ssh/id_rsa.pub." $MSGBOX_HEIGHT $TERM_WIDTH
            fi
            ;;
        3) # Add local id_rsa.pub
            if [ ! -f ~/.ssh/id_rsa.pub ]; then
                whiptail --title "Error" --msgbox "Could not find public key at ~/.ssh/id_rsa.pub.\n\nPlease generate one first." $MSGBOX_HEIGHT $TERM_WIDTH
                return
            fi

            if whiptail --title "Add Local Key" --yesno "This will add the content of ~/.ssh/id_rsa.pub to ~/.ssh/authorized_keys.\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
                {
                    echo "25" ; sleep 0.5
                    mkdir -p ~/.ssh
                    chmod 700 ~/.ssh
                    echo "50" ; sleep 0.5
                    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
                    echo "75" ; sleep 0.5
                    chmod 600 ~/.ssh/authorized_keys
                    echo "100" ; sleep 0.5
                } | whiptail --title "Adding Key" --gauge "Securing key file..." $GAUGE_HEIGHT $TERM_WIDTH 0
                whiptail --title "Success" --msgbox "Public key from ~/.ssh/id_rsa.pub added to authorized_keys." $MSGBOX_HEIGHT $TERM_WIDTH
            fi
            ;;
        4) # Paste manually
            SSH_KEY=$(whiptail --title "Paste Public Key" --inputbox "Paste your full public SSH key (e.g., ssh-rsa AAAA...):" 10 60 3>&1 1>&2 2>&3)

            if [ -z "$SSH_KEY" ]; then
                return
            fi

            {
                echo "30" ; sleep 0.5
                mkdir -p ~/.ssh
                echo "60" ; sleep 0.5
                echo "$SSH_KEY" >> ~/.ssh/authorized_keys
                echo "80" ; sleep 0.5
                chmod 700 ~/.ssh
                chmod 600 ~/.ssh/authorized_keys
                echo "100" ; sleep 0.5
            } | whiptail --title "Adding Key" --gauge "Securing key file..." $GAUGE_HEIGHT $TERM_WIDTH 0

            whiptail --title "Success" --msgbox "Public key added to ~/.ssh/authorized_keys" $MSGBOX_HEIGHT $TERM_WIDTH
            ;;
        5) # Back
            return
            ;;
    esac
}

# NEW: Install Fail2ban
CURRENT_SSH_PORT="22"
install_fail2ban() {
   get_terminal_size
   if whiptail --title "Install Fail2ban" --yesno "This will install 'fail2ban', a service that monitors logs and bans malicious IP addresses.\n\nIt provides good out-of-the-box protection for SSH.\n\nInstall?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "25" ; sleep 0.5
           sudo apt install -y fail2ban >/dev/null 2>&1
           echo "50" ; sleep 0.5
           
           if [ -f /etc/ssh/sshd_config ]; then
               local port_line
               port_line=$(grep -E "^#?Port " /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
               if [ -n "$port_line" ]; then
                   CURRENT_SSH_PORT="$port_line"
               fi
           fi
           
           # Configure fail2ban to use the current SSH port
           sudo mkdir -p /etc/fail2ban/jail.d
           echo "[sshd]" | sudo tee /etc/fail2ban/jail.d/sshd-port.conf >/dev/null
           echo "port = $CURRENT_SSH_PORT" | sudo tee -a /etc/fail2ban/jail.d/sshd-port.conf >/dev/null
           echo "75" ; sleep 0.5
           sudo systemctl enable --now fail2ban >/dev/null 2>&1
           echo "100" ; sleep 0.5
       } | whiptail --title "Installing" --gauge "Installing Fail2ban..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "Fail2ban installed and enabled successfully!\n\nConfigured to monitor SSH port: $CURRENT_SSH_PORT" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# NEW: Change SSH Port
CURRENT_PORT="22"
change_ssh_port() {
   get_terminal_size
   # Get current SSH port with safe default
   if [ -f /etc/ssh/sshd_config ]; then
       local port_line
       port_line=$(grep -E "^#?Port " /etc/ssh/sshd_config | awk '{print $2}' | tail -n 1)
       if [ -n "$port_line" ]; then
           CURRENT_PORT="$port_line"
       fi
   fi
   
   NEW_PORT=$(whiptail --title "Change SSH Port" --inputbox "Enter new SSH port number (1-65535):\n\nCurrent: $CURRENT_PORT" 12 60 "2222" 3>&1 1>&2 2>&3)

   if [ -z "$NEW_PORT" ]; then
       return
   fi
   
   if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
       whiptail --title "Error" --msgbox "Invalid port number. Must be between 1 and 65535." $MSGBOX_HEIGHT $TERM_WIDTH
       return
   fi

   if ! whiptail --title "Confirm" --yesno "WARNING: This will change your SSH port to $NEW_PORT.\n\nYou will be disconnected and must reconnect on the new port.\n\nThis script will update UFW rules and fail2ban configuration if they are installed.\n\nContinue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       return
   fi

   # Create temporary files to store messages
   local ufw_message_file=$(mktemp)
   local fail2ban_message_file=$(mktemp)
   
   {
       echo "10" ; sleep 0.5
       sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.portchange
       echo "20" ; sleep 0.5
       sudo sed -i "s/^#\?Port .*/Port $NEW_PORT/" /etc/ssh/sshd_config
       echo "40" ; sleep 0.5
       
       # Update UFW rules
       local ufw_message="UFW not found. Please manually configure firewall rules."
       if command -v ufw &> /dev/null; then
           if sudo ufw status | grep -q "Status: active"; then
               # Remove old port if it was explicitly allowed
               if sudo ufw status numbered | grep -q "$CURRENT_PORT/tcp"; then
                   sudo ufw delete allow "$CURRENT_PORT/tcp" >/dev/null 2>&1
               fi
               # Allow new port
               sudo ufw allow "$NEW_PORT/tcp" >/dev/null 2>&1
               ufw_message="UFW: Removed port $CURRENT_PORT and added $NEW_PORT."
           else
               ufw_message="UFW is installed but not active. Port $NEW_PORT was not configured."
           fi
       fi
       echo "$ufw_message" > "$ufw_message_file"
       echo "60" ; sleep 0.5
       
       # Update fail2ban configuration
       local fail2ban_message="Fail2ban is not active. No changes made."
       if systemctl is-active --quiet fail2ban 2>/dev/null; then
           sudo mkdir -p /etc/fail2ban/jail.d
           echo "[sshd]" | sudo tee /etc/fail2ban/jail.d/sshd-port.conf >/dev/null
           echo "port = $NEW_PORT" | sudo tee -a /etc/fail2ban/jail.d/sshd-port.conf >/dev/null
           sudo systemctl reload fail2ban >/dev/null 2>&1
           fail2ban_message="Fail2ban updated to monitor port $NEW_PORT."
       fi
       echo "$fail2ban_message" > "$fail2ban_message_file"
       echo "80" ; sleep 0.5
       
       sudo systemctl reload sshd
       echo "100" ; sleep 0.5
   } | whiptail --title "Changing Port" --gauge "Configuring SSH and updating services..." $GAUGE_HEIGHT $TERM_WIDTH 0

   # Read messages from temporary files
   local ufw_message=$(cat "$ufw_message_file")
   local fail2ban_message=$(cat "$fail2ban_message_file")
   
   # Clean up temporary files
   rm -f "$ufw_message_file" "$fail2ban_message_file"
   
   whiptail --title "Success" --msgbox "SSH port changed to: $NEW_PORT\n\n$ufw_message\n\n$fail2ban_message\n\nPlease log out and reconnect on the new port." $MSGBOX_HEIGHT $TERM_WIDTH
}

# NEW: Configure Timezone
configure_timezone() {
   get_terminal_size
   if whiptail --title "Configure Timezone" --yesno "This will launch the system's text-based TUI to configure your timezone.\n\nPress OK to continue." $MSGBOX_HEIGHT $TERM_WIDTH; then
       sudo dpkg-reconfigure tzdata
       whiptail --title "Success" --msgbox "Timezone configuration complete." $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}


# System Settings Submenu
system_settings_menu() {
   get_terminal_size
   while true; do
       CHOICE=$(whiptail --title "System Settings" --menu "Choose an option:" $MENU_HEIGHT $TERM_WIDTH 11 \
           "1" "Change Hostname" \
           "2" "View System Usage" \
           "3" "Harden SSH" \
           "4" "Configure UFW" \
           "5" "Add New User" \
           "6" "Manage SSH Keys" \
           "7" "Install Fail2ban" \
           "8" "Change Default SSH Port" \
           "9" "Configure Timezone" \
           "10" "Back to Main Menu" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) change_hostname ;;
           2) view_system_usage ;;
           3) harden_ssh ;;
           4) configure_ufw ;;
           5) add_new_user ;;
           6) manage_ssh_keys ;;
           7) install_fail2ban ;;
           8) change_ssh_port ;;
           9) configure_timezone ;;
           10) break ;;
       esac
   done
}

# --- Network Settings Functions ---

# Set Static IP
set_static_ip() {
    get_terminal_size
    if ! command -v netplan &>/dev/null; then
        whiptail --title "Unsupported System" --msgbox "This feature requires 'netplan' (found on Ubuntu 17.10+).\n\nYour system does not appear to use netplan. Manual configuration is required." $MSGBOX_HEIGHT $TERM_WIDTH
        return
    fi

    # Get network interface
    local INTERFACES
    INTERFACES=$(ip -br link show | grep -v "lo" | awk '{print $1}')
    local INTERFACE_ARRAY=()
    while IFS= read -r iface; do
        INTERFACE_ARRAY+=("$iface" "")
    done <<< "$INTERFACES"

    local INTERFACE
    INTERFACE=$(whiptail --title "Select Interface" --menu "Choose network interface:" 16 60 5 "${INTERFACE_ARRAY[@]}" 3>&1 1>&2 2>&3)

    if [ -z "$INTERFACE" ]; then
        return
    fi

    local IP_ADDRESS NETMASK GATEWAY DNS1 DNS2
    IP_ADDRESS=$(whiptail --title "Static IP" --inputbox "Enter IP address (e.g., 192.168.1.100):" 10 60 3>&1 1>&2 2>&3)
    NETMASK=$(whiptail --title "Static IP" --inputbox "Enter netmask (e.g., 255.255.255.0 or 24):" 10 60 "24" 3>&1 1>&2 2>&3)
    GATEWAY=$(whiptail --title "Static IP" --inputbox "Enter gateway (e.g., 192.168.1.1):" 10 60 3>&1 1>&2 2>&3)
    DNS1=$(whiptail --title "DNS Servers" --inputbox "Enter primary DNS server:" 10 60 "8.8.8.8" 3>&1 1>&2 2>&3)
    DNS2=$(whiptail --title "DNS Servers" --inputbox "Enter secondary DNS server (optional):" 10 60 "1.1.1.1" 3>&1 1>&2 2>&3)

    if [ -z "$IP_ADDRESS" ] || [ -z "$GATEWAY" ] || [ -z "$DNS1" ]; then
        whiptail --title "Error" --msgbox "IP address, gateway, and primary DNS are required." $MSGBOX_HEIGHT $TERM_WIDTH
        return
    fi

    local DNS_SERVERS="[$DNS1"
    if [ -n "$DNS2" ]; then
        DNS_SERVERS="$DNS_SERVERS, $DNS2]"
    else
        DNS_SERVERS="$DNS_SERVERS]"
    fi

    local CONFIG_FILE="/etc/netplan/99-gemini-static.yaml"
    local CONFIG_CONTENT="network:
  version: 2
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses: [$IP_ADDRESS/$NETMASK]
      gateway4: $GATEWAY
      nameservers:
        addresses: $DNS_SERVERS"

    if whiptail --title "Confirm Configuration" --yesno "This will create a new netplan file:\n$CONFIG_FILE\n\nWith the following content:\n$CONFIG_CONTENT\n\nApplying this may disconnect your session. Proceed?" $MSGBOX_HEIGHT $TERM_WIDTH; then
        echo "$CONFIG_CONTENT" | sudo tee "$CONFIG_FILE" >/dev/null
        {
            echo 50 ; sleep 1
            sudo netplan apply
            echo 100
        } | whiptail --gauge "Applying network configuration..." $GAUGE_HEIGHT $TERM_WIDTH 0
        whiptail --title "Success" --msgbox "Static IP configuration applied.\n\nA backup of your previous netplan config was not made. Please review the changes.\n\nNew IP: $IP_ADDRESS" $MSGBOX_HEIGHT $TERM_WIDTH
    fi
}

# Change DNS Servers
change_dns() {
    local DNS1 DNS2
    DNS1=$(whiptail --title "DNS Servers" --inputbox "Enter primary DNS server:\n(e.g., 1.1.1.1 for Cloudflare, 8.8.8.8 for Google)" 12 60 "1.1.1.1" 3>&1 1>&2 2>&3)
    DNS2=$(whiptail --title "DNS Servers" --inputbox "Enter secondary DNS server (optional):" 10 60 "1.0.0.1" 3>&1 1>&2 2>&3)

    if [ -z "$DNS1" ]; then
        return
    fi

    # Check if systemd-resolved is managing resolv.conf
    if [[ -L /etc/resolv.conf ]] && [[ "$(readlink /etc/resolv.conf)" == *systemd* ]]; then
        whiptail --title "Info" --msgbox "Systemd-resolved detected. DNS will be configured in /etc/systemd/resolved.conf." 10 60
        {
            echo 25; sleep 0.5
            sudo cp /etc/systemd/resolved.conf /etc/systemd/resolved.conf.bak
            local dns_servers="$DNS1"
            [ -n "$DNS2" ] && dns_servers="$dns_servers $DNS2"
            sudo sed -i -E "s/^#?DNS=.*/DNS=$dns_servers/" /etc/systemd/resolved.conf
            if ! grep -q "^DNS=" /etc/systemd/resolved.conf; then
                echo "DNS=$dns_servers" | sudo tee -a /etc/systemd/resolved.conf > /dev/null
            fi
            echo 75; sleep 0.5
            sudo systemctl restart systemd-resolved
            echo 100;
        } | whiptail --title "Updating DNS" --gauge "Configuring systemd-resolved..." 8 60 0
        whiptail --title "Success" --msgbox "DNS servers updated via systemd-resolved.\nBackup of config saved to /etc/systemd/resolved.conf.bak" 10 60
    else
        {
            echo 50 ; sleep 0.5
            echo "nameserver $DNS1" | sudo tee /etc/resolv.conf >/dev/null
            if [ -n "$DNS2" ]; then
                echo "nameserver $DNS2" | sudo tee -a /etc/resolv.conf >/dev/null
            fi
            echo 100 ; sleep 0.5
        } | whiptail --title "Updating DNS" --gauge "Writing to /etc/resolv.conf..." 8 60 0
        whiptail --title "Success" --msgbox "DNS servers updated in /etc/resolv.conf.\n\nNote: These changes may be temporary if your system uses a network manager." 12 60
    fi
}

# Network Settings Submenu
network_settings_menu() {
   while true; do
       CHOICE=$(whiptail --title "Network Settings" --menu "Choose an option:" 14 60 4 \
           "1" "Set Static IP" \
           "2" "Change DNS Servers" \
           "3" "Back to Main Menu" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) set_static_ip ;;
           2) change_dns ;;
           3) break ;;
       esac
   done
}

# --- Others Submenu Functions ---

# Configure Aliases
configure_aliases() {
    if whiptail --title "Configure Aliases" --yesno "This will add useful shell aliases to ~/.alias and source them in your shell's RC file.\n\nNOTE: The 'alias' file must exist in the script's directory.\n\nDo you want to continue?" 14 60; then
        local rc_file_path
        rc_file_path=$(add_alias 2>&1)
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            whiptail --title "Success" --msgbox "Aliases configured successfully.\nSourced in: $rc_file_path\n\nPlease run 'source $rc_file_path' to apply the changes." 12 60
        else
            whiptail --title "Error" --msgbox "Failed to configure aliases:\n\n$rc_file_path" 12 60
        fi
    fi
}
# Configure Git
configure_git() {
   GIT_USERNAME=$(whiptail --title "Configure Git" --inputbox "Enter Git username:" 10 60 3>&1 1>&2 2>&3)

   if [ -z "$GIT_USERNAME" ]; then
       return
   fi

   GIT_EMAIL=$(whiptail --title "Configure Git" --inputbox "Enter Git email:" 10 60 3>&1 1>&2 2>&3)

   if [ -z "$GIT_EMAIL" ]; then
       return
   fi

   {
       echo "50" ; sleep 0.5
       git config --global user.name "$GIT_USERNAME"
       git config --global user.email "$GIT_EMAIL"
       echo "100" ; sleep 0.5
   } | whiptail --title "Configuring" --gauge "Setting up Git profile..." 8 60 0

   whiptail --title "Success" --msgbox "Git configured:\n\nName: $GIT_USERNAME\nEmail: $GIT_EMAIL" 10 60
}

# Others Submenu
others_menu() {
   while true; do
       CHOICE=$(whiptail --title "Others" --menu "Choose an option:" 14 60 4 \
           "1" "Configure Aliases" \
           "2" "Configure Git" \
           "3" "Back to Main Menu" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) configure_aliases ;;
           2) configure_git ;;
           3) break ;;
       esac
   done
}

# --- NEW: Maintenance Functions ---

# NEW: Run System Cleanup
run_system_cleanup() {
   if whiptail --title "Run System Cleanup" --yesno "This will perform a system cleanup:\n- Autoremove old packages\n- Clear apt cache\n- Vacuum systemd logs to 2 weeks\n\nContinue?" 14 60; then
       {
           echo "0" ; echo "XXX" ; echo "Running apt autoremove..." ; echo "XXX" ; sleep 0.5
           sudo apt autoremove -y >/dev/null 2>&1
           echo "33" ; echo "XXX" ; echo "Running apt clean..." ; echo "XXX" ; sleep 0.5
           sudo apt clean >/dev/null 2>&1
           echo "66" ; echo "XXX" ; echo "Vacuuming journal logs..." ; echo "XXX" ; sleep 0.5
           sudo journalctl --vacuum-time=2weeks >/dev/null 2>&1
           echo "100" ; echo "XXX" ; echo "Cleanup complete." ; echo "XXX" ; sleep 0.5
       } | whiptail --title "Cleaning System" --gauge "Running cleanup tasks..." 8 60 0
       
       whiptail --title "Success" --msgbox "System cleanup completed successfully." 8 50
   fi
}

# NEW: Prune Docker System
prune_docker_system() {
   if ! command -v docker &> /dev/null; then
       whiptail --title "Error" --msgbox "Docker is not installed. Please install it from the 'Install Packages' menu." 10 60
       return
   fi
   
   if whiptail --title "Prune Docker System" --yesno "WARNING: This will remove ALL unused Docker data:\n- All stopped containers\n- All unused networks\n- All dangling images\n- All build cache\n\nThis is irreversible!\n\nContinue?" 16 60; then
       {
           echo "50" ; sleep 0.5
           sudo docker system prune -af >/dev/null 2>&1
           echo "100" ; sleep 0.5
       } | whiptail --title "Pruning Docker" --gauge "Cleaning up Docker..." 8 60 0
       
       whiptail --title "Success" --msgbox "Docker system prune completed." 8 50
   fi
}

# NEW: Maintenance Submenu
maintenance_menu() {
   while true; do
       CHOICE=$(whiptail --title "Maintenance" --menu "Choose an option:" 14 60 4 \
           "1" "Run System Cleanup" \
           "2" "Prune Docker System" \
           "3" "Back to Main Menu" 3>&1 1>&2 2>&3)
           
       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) run_system_cleanup ;;
           2) prune_docker_system ;;
           3) break ;;
       esac
   done
}


# --- Main Menu ---

main_menu() {
   while true; do
       CHOICE=$(whiptail --title "System Configuration Menu" --menu "Choose an option:" 20 60 9 \
           "1" "System Updates" \
           "2" "Install Packages" \
           "3" "Create MOTD" \
           "4" "System Settings" \
           "5" "Network Settings" \
           "6" "Maintenance" \
           "7" "Others" \
           "8" "Exit" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           exit 0
       fi

       case $CHOICE in
           1) system_update ;;
           2) install_packages_menu ;;
           3) create_motd ;;
           4) system_settings_menu ;;
           5) network_settings_menu ;;
           6) maintenance_menu ;;
           7) others_menu ;;
           8) exit 0 ;;
       esac
   done
}

# Update main menu to use dynamic dimensions
main_menu() {
   get_terminal_size
   while true; do
       CHOICE=$(whiptail --title "System Configuration Menu" --menu "Choose an option:" $TERM_HEIGHT $TERM_WIDTH 9 \
           "1" "System Updates" \
           "2" "Install Packages" \
           "3" "Create MOTD" \
           "4" "System Settings" \
           "5" "Network Settings" \
           "6" "Maintenance" \
           "7" "Others" \
           "8" "Exit" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           exit 0
       fi

       case $CHOICE in
           1) system_update ;;
           2) install_packages_menu ;;
           3) create_motd ;;
           4) system_settings_menu ;;
           5) network_settings_menu ;;
           6) maintenance_menu ;;
           7) others_menu ;;
           8) exit 0 ;;
       esac
   done
}

# Update system_update to use dynamic dimensions
system_update() {
   get_terminal_size
   if whiptail --title "System Updates" --yesno "This will update and upgrade all system packages.\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "10" ; sleep 0.5
           sudo apt-get update >/dev/null 2>&1
           echo "50" ; sleep 0.5
           sudo apt-get upgrade -y >/dev/null 2>&1
           echo "90" ; sleep 0.5
           sudo apt-get autoremove -y >/dev/null 2>&1
           echo "100" ; sleep 0.5
       } | whiptail --title "System Updates" --gauge "Updating system packages..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "System updates completed successfully!" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# Update install_packages_menu to use dynamic dimensions
install_packages_menu() {
   get_terminal_size
   while true; do
       CHOICE=$(whiptail --title "Install Packages" --menu "Choose an option:" $MENU_HEIGHT $TERM_WIDTH 6 \
           "1" "Install Base Packages" \
           "2" "Install Docker" \
           "3" "Install Dev Packages" \
           "4" "Install ALL (Base, Docker, Dev)" \
           "5" "Back to Main Menu" 3>&1 1>&2 2>&3)

       exitstatus=$?
       if [ $exitstatus != 0 ]; then
           break
       fi

       case $CHOICE in
           1) install_base ;;
           2) install_docker ;;
           3) install_dev ;;
           4) install_all ;;
           5) break ;;
       esac
   done
}

# Update install_base to use dynamic dimensions
install_base() {
   get_terminal_size
   if whiptail --title "Install Base Packages" --yesno "This will install base packs like: git, gh, nano\n\nDo you want to continue?" $MSGBOX_HEIGHT $TERM_WIDTH; then
       {
           echo "33" ; sleep 0.5
           _install_base_logic
           echo "100" ; sleep 0.5
       } | whiptail --title "Installing" --gauge "Installing base packages..." $GAUGE_HEIGHT $TERM_WIDTH 0

       whiptail --title "Success" --msgbox "Base packages installed successfully!" $MSGBOX_HEIGHT $TERM_WIDTH
   fi
}

# Main execution
check_root
verify_sudo
main_menu

