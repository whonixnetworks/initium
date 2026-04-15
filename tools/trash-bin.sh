#!/usr/bin/env bash
# trash-bin — System trash management and safe file deletion
# author: greedy
# version: 1.1.0

set -euo pipefail

# CONFIGURATION variables (UPPERCASE, top of file, with comments)
TRASH_BASE="/trash"                     # shouldn't use user-specific trash location
INSTALL_DIR="/usr/local/bin"            # shouldn't install to system directories
MAX_AGE_DAYS=7                          # shouldn't keep trash indefinitely
MAX_SIZE_GB=5                           # shouldn't allow unlimited trash growth
VERSION="1.1.0"

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

# Error handling
die() {
    log_error "FATAL: $1"
    exit 1
}

# Check if running as root for install
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This installer must be run as root"
    fi
}

# Install the trash system
install_trash_system() {
    check_root

    echo "======================================"
    echo "  Easy Trash System Installer v${VERSION}"
    echo "======================================"
    echo ""

    # Create trash directory with proper permissions
    log_success "Creating trash directory at $TRASH_BASE"
    mkdir -p "$TRASH_BASE"
    chmod 1777 "$TRASH_BASE"

    # Backup original rm if it exists and isn't already backed up
    if [[ -f /bin/rm ]] && [[ ! -f /bin/rm.original ]]; then
        log_success "Backing up original rm to /bin/rm.original"
        cp /bin/rm /bin/rm.original
    fi

    # Install safe-rm wrapper
    log_success "Installing safe-rm wrapper"
    cat > "$INSTALL_DIR/safe-rm" << 'SAFE_RM_EOF'
#!/bin/bash
# Safe RM wrapper - moves files to trash instead of deleting
exec 2>/dev/null  # Redirect all stderr to /dev/null
TRASH_BASE="/trash"
DATE_DIR="$(date +%Y-%m-%d)"
TRASH_DIR="$TRASH_BASE/$DATE_DIR"

# Create dated trash directory if it doesn't exist
if [[ ! -d "$TRASH_DIR" ]]; then
    mkdir -p "$TRASH_DIR" 2>/dev/null || {
        if command -v sudo &>/dev/null && [[ $EUID -ne 0 ]]; then
            sudo mkdir -p "$TRASH_DIR" 2>/dev/null
            sudo chmod 1777 "$TRASH_DIR" 2>/dev/null
        fi
    }
fi

# Ensure proper permissions
chmod 1777 "$TRASH_DIR" 2>/dev/null || true

# Parse arguments
VERBOSE=false
FILES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true; shift ;;
        -r|-R|--recursive|-f|--force|-i|--interactive) shift ;;
        --help)
            echo "safe-rm: Files are moved to $TRASH_BASE/<date>/"
            echo "Use 'bypass-rm' to permanently delete files"
            echo "Use 'trash-restore' to restore files"
            echo "Trash is automatically cleaned after 7 days"
            exit 0
            ;;
        -*) shift ;;
        *) FILES+=("$1"); shift ;;
    esac
done

# If no files specified, show usage
if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "Usage: rm [OPTION]... FILE..."
    echo "Files are moved to trash at $TRASH_BASE/<date>/"
    exit 1
fi

# Process each file
for file in "${FILES[@]}"; do
    if [[ ! -e "$file" && ! -L "$file" ]]; then
        echo "rm: cannot remove '$file': No such file or directory" >&2
        continue
    fi
    
    # Generate unique name in trash
    basename_file=$(basename "$file")
    timestamp=$(date +%s)
    random_suffix=$(openssl rand -hex 3 2>/dev/null || od -An -N3 -tx1 /dev/urandom | tr -d ' ')
    unique_name="${timestamp}_${random_suffix}_${basename_file}"
    trash_path="$TRASH_DIR/$unique_name"
    
    # Move to trash
    if mv -f "$file" "$trash_path" 2>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && echo "moved '$file' to trash"
        
        # Store metadata with proper permissions handling
        TRASH_INFO="$TRASH_DIR/.trash-info"
        {
            echo "---"
            echo "trashed_file=$unique_name"
            echo "original_path=$(cd "$(dirname "$file")" 2>/dev/null && pwd || echo "$PWD")/$(basename "$file")"
            echo "deletion_date=$(date --iso-8601=seconds 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%S%z")"
            echo "deleted_by=${USER:-unknown}"
        } >> "$TRASH_INFO" 2>/dev/null || {
            touch "$TRASH_INFO" 2>/dev/null || true
            chmod 666 "$TRASH_INFO" 2>/dev/null || true
        }
    else
        echo "rm: cannot remove '$file': Permission denied or move failed" >&2
    fi
done

exit 0
SAFE_RM_EOF
    chmod +x "$INSTALL_DIR/safe-rm"

    # Install rm wrapper
    log_success "Installing rm wrapper"
    cat > /usr/bin/rm << 'RM_WRAPPER_EOF'
#!/bin/bash
exec /usr/local/bin/safe-rm "$@"
RM_WRAPPER_EOF
    chmod +x /usr/bin/rm

    # Install bypass-rm (for real deletion)
    log_success "Installing bypass-rm command"
    cat > "$INSTALL_DIR/bypass-rm" << 'BYPASS_EOF'
#!/bin/bash
# Really delete files (bypass trash)
if [[ -f /bin/rm.original ]]; then
    exec /bin/rm.original "$@"
else
    exec /bin/busybox rm "$@" 2>/dev/null || {
        echo "Error: Cannot find original rm command"
        exit 1
    }
fi
BYPASS_EOF
    chmod +x "$INSTALL_DIR/bypass-rm"

    # Install trash-restore
    log_success "Installing trash-restore command"
    cat > "$INSTALL_DIR/trash-restore" << 'RESTORE_EOF'
#!/bin/bash
TRASH_BASE="/trash"

# Colors
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; MAGENTA="\033[1;35m"
BRIGHT_CYAN="\033[0;96m"; RESET="\033[0m"

if [[ $# -eq 0 ]]; then
    clear
    HEADER_TEXT="TRASH RESTORE"
    TERM_WIDTH=${COLUMNS:-80}
    HEADER_PAD=$(( (TERM_WIDTH - ${#HEADER_TEXT} - 2) / 2 ))
    HEADER_LINE=$(printf "%*s" $HEADER_PAD "" | tr " " "•")
    echo -e "  ${CYAN}${HEADER_LINE} ${RED}${HEADER_TEXT}${RESET}${CYAN} ${HEADER_LINE}${RESET}\n"
    
    echo -e "  ${GREEN}● Usage:${RESET} trash-restore ${WHITE}<filename>${RESET}\n"
    echo -e "  ${YELLOW}▼ Available files in trash:${RESET}\n"
    
    FILES=$(find "$TRASH_BASE" -type f ! -name ".trash-info" 2>/dev/null | head -20)
    if [[ -z "$FILES" ]]; then
        echo -e "    ${BRIGHT_CYAN}└─${RESET} ${MAGENTA}No files in trash${RESET}\n"
    else
        echo "$FILES" | while read -r filepath; do
            filename=$(basename "$filepath" | sed 's/^[0-9]*_[a-f0-9]*_//')
            echo -e "    ${BRIGHT_CYAN}├─${RESET} ${WHITE}${filename}${RESET}"
        done | head -19
        echo "$FILES" | tail -1 | while read -r filepath; do
            filename=$(basename "$filepath" | sed 's/^[0-9]*_[a-f0-9]*_//')
            echo -e "    ${BRIGHT_CYAN}└─${RESET} ${WHITE}${filename}${RESET}"
        done
        echo
    fi
    exit 1
fi

SEARCH_NAME="$1"
FOUND_FILE=$(find "$TRASH_BASE" -type f -name "*$SEARCH_NAME*" ! -name ".trash-info" 2>/dev/null | head -1)

if [[ -z "$FOUND_FILE" ]]; then
    echo -e "  ${RED}✗ File not found in trash${RESET}"
    exit 1
fi

FOUND_BASENAME=$(basename "$FOUND_FILE")
TRASH_DIR=$(dirname "$FOUND_FILE")
INFO_FILE="$TRASH_DIR/.trash-info"

# Read original path if available
if [[ -f "$INFO_FILE" ]]; then
    ORIGINAL_PATH=$(grep -A3 "trashed_file=$FOUND_BASENAME" "$INFO_FILE" | grep "original_path=" | cut -d= -f2)
    if [[ -n "$ORIGINAL_PATH" ]]; then
        echo -e "  ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}Original:${RESET} ${WHITE}${ORIGINAL_PATH}${RESET}"
    fi
fi

# Restore to current directory
BASENAME=$(basename "$FOUND_FILE" | sed 's/^[0-9]*_[a-f0-9]*_//')
mv "$FOUND_FILE" "./$BASENAME"

# Remove entry from .trash-info
if [[ -f "$INFO_FILE" ]]; then
    sed -i "/trashed_file=$FOUND_BASENAME/,+4d" "$INFO_FILE" 2>/dev/null || true
fi

echo -e "  ${BRIGHT_CYAN}└─${RESET} ${GREEN}Restored to:${RESET} ${WHITE}./$BASENAME${RESET}\n"
RESTORE_EOF
    chmod +x "$INSTALL_DIR/trash-restore"

    # Install trash-list
    log_success "Installing trash-list command"
    cat > "$INSTALL_DIR/trash-list" << 'LIST_EOF'
#!/bin/bash
TRASH_BASE="/trash"

# Colors
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; MAGENTA="\033[1;35m"
BRIGHT_CYAN="\033[0;96m"; RESET="\033[0m"

clear
HEADER_TEXT="TRASH LIST"
TERM_WIDTH=${COLUMNS:-80}
HEADER_PAD=$(( (TERM_WIDTH - ${#HEADER_TEXT} - 2) / 2 ))
HEADER_LINE=$(printf "%*s" $HEADER_PAD "" | tr " " "•")
echo -e "  ${CYAN}${HEADER_LINE} ${RED}${HEADER_TEXT}${RESET}${CYAN} ${HEADER_LINE}${RESET}\n"

TOTAL_SIZE=$(du -sh "$TRASH_BASE" 2>/dev/null | awk '{print $1}')
TOTAL_FILES=$(find "$TRASH_BASE" -type f ! -name ".trash-info" 2>/dev/null | wc -l)

echo -e "  ${GREEN}● Total Size:${RESET}  ${WHITE}${TOTAL_SIZE}${RESET}"
echo -e "  ${GREEN}● Total Files:${RESET} ${WHITE}${TOTAL_FILES}${RESET}\n"

if [[ $TOTAL_FILES -eq 0 ]]; then
    echo -e "  ${YELLOW}▼ Trash is empty${RESET}\n"
    exit 0
fi

echo -e "  ${YELLOW}▼ Recent files:${RESET}\n"
echo -e "    ${MAGENTA}Size${RESET}            ${MAGENTA}Date${RESET}                 ${MAGENTA}Filename${RESET}"
echo -e "    ${CYAN}$(printf '%.0s─' {1..70})${RESET}"

find "$TRASH_BASE" -type f ! -name ".trash-info" -printf "%T@ %p\n" 2>/dev/null | \
    sort -rn | head -20 | while read timestamp filepath; do
    filename=$(basename "$filepath" | sed 's/^[0-9]*_[a-f0-9]*_//')
    filedate=$(date -d "@${timestamp%.*}" "+%Y-%m-%d %H:%M" 2>/dev/null || date -r "${timestamp%.*}" "+%Y-%m-%d %H:%M" 2>/dev/null)
    size=$(du -h "$filepath" 2>/dev/null | cut -f1)
    printf "    ${BRIGHT_CYAN}├─${RESET} ${WHITE}%-10s${RESET}  ${WHITE}%-20s${RESET} ${WHITE}%s${RESET}\n" "$size" "$filedate" "$filename"
done

echo
LIST_EOF
    chmod +x "$INSTALL_DIR/trash-list"

    # Install trash-empty
    log_success "Installing trash-empty command"
    cat > "$INSTALL_DIR/trash-empty" << 'EMPTY_EOF'
#!/bin/bash
TRASH_BASE="/trash"

# Colors
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; MAGENTA="\033[1;35m"
BRIGHT_CYAN="\033[0;96m"; RESET="\033[0m"

if [[ $EUID -ne 0 ]]; then
    echo -e "  ${RED}✗ This command requires root privileges${RESET}"
    echo -e "  ${YELLOW}▼ Usage:${RESET} ${WHITE}sudo trash-empty${RESET}\n"
    exit 1
fi

TOTAL_FILES=$(find "$TRASH_BASE" -type f ! -name ".trash-info" 2>/dev/null | wc -l)
TOTAL_SIZE=$(du -sh "$TRASH_BASE" 2>/dev/null | awk '{print $1}')

clear
HEADER_TEXT="EMPTY TRASH"
TERM_WIDTH=${COLUMNS:-80}
HEADER_PAD=$(( (TERM_WIDTH - ${#HEADER_TEXT} - 2) / 2 ))
HEADER_LINE=$(printf "%*s" $HEADER_PAD "" | tr " " "•")
echo -e "  ${CYAN}${HEADER_LINE} ${RED}${HEADER_TEXT}${RESET}${CYAN} ${HEADER_LINE}${RESET}\n"

if [[ $TOTAL_FILES -eq 0 ]]; then
    echo -e "  ${GREEN}● Trash is already empty${RESET}\n"
    exit 0
fi

echo -e "  ${YELLOW}▼ About to permanently delete:${RESET}\n"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}Files:${RESET} ${WHITE}${TOTAL_FILES}${RESET}"
echo -e "    ${BRIGHT_CYAN}└─${RESET} ${MAGENTA}Size:${RESET}  ${WHITE}${TOTAL_SIZE}${RESET}\n"

printf "  ${RED}▼ Are you sure? (yes/no):${RESET} "
read -r REPLY
echo

if [[ $REPLY == "yes" ]]; then
    echo -e "  ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}Emptying trash...${RESET}"
    
    if [[ -f /bin/rm.original ]]; then
        /bin/rm.original -rf "$TRASH_BASE"/* 2>/dev/null
    else
        /bin/busybox rm -rf "$TRASH_BASE"/* 2>/dev/null
    fi
    
    mkdir -p "$TRASH_BASE"
    chmod 1777 "$TRASH_BASE"
    
    echo -e "  ${BRIGHT_CYAN}└─${RESET} ${GREEN}Trash emptied successfully${RESET}\n"
else
    echo -e "  ${BRIGHT_CYAN}└─${RESET} ${YELLOW}Operation cancelled${RESET}\n"
fi
EMPTY_EOF
    chmod +x "$INSTALL_DIR/trash-empty"

    # Install trash-info
    log_success "Installing trash-info command"
    cat > "$INSTALL_DIR/trash-info" << 'INFO_EOF'
#!/bin/bash
TRASH_BASE="/trash"

# Colors
RED="\033[1;31m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; MAGENTA="\033[1;35m"
BRIGHT_CYAN="\033[0;96m"; RESET="\033[0m"

TOTAL_SIZE=$(du -sh "$TRASH_BASE" 2>/dev/null | awk '{print $1}')
TOTAL_FILES=$(find "$TRASH_BASE" -type f ! -name ".trash-info" 2>/dev/null | wc -l)

clear
HEADER_TEXT="TRASH SYSTEM"
TERM_WIDTH=${COLUMNS:-80}
HEADER_PAD=$(( (TERM_WIDTH - ${#HEADER_TEXT} - 2) / 2 ))
HEADER_LINE=$(printf "%*s" $HEADER_PAD "" | tr " " "•")
echo -e "  ${CYAN}${HEADER_LINE} ${RED}${HEADER_TEXT}${RESET}${CYAN} ${HEADER_LINE}${RESET}\n"

echo -e "  ${GREEN}● Trash Location:${RESET}      ${WHITE}${TRASH_BASE}${RESET}"
echo -e "  ${GREEN}● Retention Period:${RESET}    ${WHITE}7 days${RESET}"
echo -e "  ${GREEN}● Size Limit Warning:${RESET}  ${WHITE}5GB${RESET}"
echo -e "  ${GREEN}● Current Size:${RESET}        ${WHITE}${TOTAL_SIZE}${RESET}"
echo -e "  ${GREEN}● Total Files:${RESET}         ${WHITE}${TOTAL_FILES}${RESET}\n"

echo -e "  ${YELLOW}▼ Commands:${RESET}\n"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}rm <file>${RESET}              ${WHITE}Move file to trash${RESET}"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}bypass-rm <file>${RESET}       ${WHITE}Really delete file (use with caution!)${RESET}"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}trash-restore <file>${RESET}   ${WHITE}Restore file from trash${RESET}"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}trash-list${RESET}             ${WHITE}List all files in trash${RESET}"
echo -e "    ${BRIGHT_CYAN}├─${RESET} ${MAGENTA}sudo trash-empty${RESET}       ${WHITE}Empty entire trash${RESET}"
echo -e "    ${BRIGHT_CYAN}└─${RESET} ${MAGENTA}trash-info${RESET}             ${WHITE}Show this information${RESET}\n"
INFO_EOF
    chmod +x "$INSTALL_DIR/trash-info"

    # Install cleanup cron job
    log_success "Installing automatic cleanup (7 days retention)"
    cat > /etc/cron.daily/trash-cleanup << 'CLEANUP_EOF'
#!/bin/bash
TRASH_BASE="/trash"
MAX_AGE_DAYS=7

find "$TRASH_BASE" -maxdepth 1 -type d -name "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]" -mtime +$MAX_AGE_DAYS -exec rm -rf {} \; 2>/dev/null

exit 0
CLEANUP_EOF
    chmod +x /etc/cron.daily/trash-cleanup

    log_success "Installation complete!"
    echo ""
    echo "Run 'trash-info' to see available commands"
    echo ""
}

# Uninstall the trash system
uninstall_trash_system() {
    check_root

    echo "======================================"
    echo "  Uninstalling Trash System"
    echo "======================================"
    echo ""

    # Restore original rm
    if [[ -f /bin/rm.original ]]; then
        log_success "Restoring original rm"
        mv /bin/rm.original /usr/bin/rm
    fi

    # Remove installed scripts
    log_success "Removing trash commands"
    rm -f "$INSTALL_DIR/safe-rm"
    rm -f "$INSTALL_DIR/bypass-rm"
    rm -f "$INSTALL_DIR/trash-restore"
    rm -f "$INSTALL_DIR/trash-list"
    rm -f "$INSTALL_DIR/trash-empty"
    rm -f "$INSTALL_DIR/trash-info"
    rm -f /etc/cron.daily/trash-cleanup

    log_warning "Trash directory ($TRASH_BASE) was NOT deleted"
    echo "To remove it manually: sudo rm -rf $TRASH_BASE"
    echo ""
    log_success "Uninstall complete!"
}

# Help system
show_help() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Trash Bin v${VERSION}${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo
    echo -e "${CYAN}Usage:${NC}"
    echo -e "  ${WHITE}sudo ./trash-bin.sh [COMMAND]${NC}"
    echo
    echo -e "${MAGENTA}=== Commands ===${NC}"
    echo -e "  ${GREEN}✓${NC} ${WHITE}install${NC}     Install trash system"
    echo -e "  ${GREEN}✓${NC} ${WHITE}uninstall${NC}   Uninstall trash system"
    echo -e "  ${BLUE}ℹ${NC} ${WHITE}-h, --help${NC}   Show this help"
    echo -e "  ${BLUE}ℹ${NC} ${WHITE}-v, --version${NC} Show version"
    echo
    echo -e "${MAGENTA}=== Description ===${NC}"
    echo -e "  System trash management and safe file deletion tool."
    echo -e "  Replaces rm with a safe version that moves files to trash."
    echo
    echo -e "${MAGENTA}=== Examples ===${NC}"
    echo -e "  ${GRAY}sudo ./trash-bin.sh install${NC}"
    echo -e "  ${GRAY}sudo ./trash-bin.sh uninstall${NC}"
    echo
}

# Main script logic
case "${1:-}" in
    install)
        install_trash_system
        ;;
    uninstall)
        uninstall_trash_system
        ;;
    -h|--help)
        show_help
        exit 0
        ;;
    -v|--version)
        echo "trash-bin v${VERSION}"
        exit 0
        ;;
    *)
        show_help
        exit 1
        ;;
esac
