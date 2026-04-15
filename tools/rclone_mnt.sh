#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════════
#  Rclone Mount/Unmount/Status/Restart Script for Google Drive
#  Usage: ./rclone.sh --mount | --unmount | --status | --restart
# ════════════════════════════════════════════════════════════════════════════════

# ── Configuration ───────────────────────────────────────────────────────────────
REMOTE="GCrypt"
REMOTE_PATH=""
MOUNT_PATH="/home/greedy/crypt"
LOG_FILE="$HOME/.rclone/mount.log"
CACHE_DIR="$HOME/.cache/rclone/vfs/$REMOTE/$REMOTE_PATH"
MAX_RETRIES=5

# ── Colors ──────────────────────────────────────────────────────────────────────
BOLD="\033[1m"
DIM="\033[2m"
RESET="\033[0m"

BRIGHT_YELLOW_BOLD="\033[1;93m"
BRIGHT_CYAN_BOLD="\033[1;96m"
BRIGHT_MAGENTA_BOLD="\033[1;95m"
BRIGHT_RED_BOLD="\033[1;91m"
GREEN="\033[0;32m"
RED="\033[0;31m"
WHITE="\033[0;97m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
YELLOW="\033[0;33m"

# ── Initialize ──────────────────────────────────────────────────────────────────
mkdir -p "$MOUNT_PATH"
mkdir -p "$(dirname "$LOG_FILE")"

# ── Helper: Check Mount ─────────────────────────────────────────────────────────
is_mounted() {
    mountpoint -q "$MOUNT_PATH" 2>/dev/null
}

# ── Helper: Format Bytes ────────────────────────────────────────────────────────
format_bytes() {
    local bytes=$1
    if [ $bytes -lt 1024 ]; then
        echo "${bytes}B"
    elif [ $bytes -lt 1048576 ]; then
        echo "$(( bytes / 1024 ))KB"
    elif [ $bytes -lt 1073741824 ]; then
        echo "$(( bytes / 1048576 ))MB"
    else
        echo "$(( bytes / 1073741824 ))GB"
    fi
}

# ── Unmount ─────────────────────────────────────────────────────────────────────
force_unmount() {
    echo -e "${RED}Unmounting $MOUNT_PATH...${RESET}"

    pkill -f "rclone mount.*$MOUNT_PATH" 2>/dev/null
    sleep 1

    if command -v fusermount3 &>/dev/null; then
        fusermount3 -uz "$MOUNT_PATH" 2>/dev/null
    fi
    if command -v fusermount &>/dev/null; then
        fusermount -uz "$MOUNT_PATH" 2>/dev/null
    fi

    sleep 1

    if is_mounted; then
        echo -e "${YELLOW}Could not unmount, trying sudo...${RESET}"
        sudo umount -l "$MOUNT_PATH" 2>/dev/null
    fi

    if ! is_mounted; then
        echo -e "${GREEN}Successfully unmounted${RESET}"
        return 0
    else
        echo -e "${RED}ERROR: Failed to unmount${RESET}"
        return 1
    fi
}

# ── Mount ───────────────────────────────────────────────────────────────────────
mount_drive() {
    if is_mounted; then
        echo -e "${CYAN}Already mounted at $MOUNT_PATH${RESET}"
        return 0
    fi

    pkill -f "rclone mount.*$MOUNT_PATH" 2>/dev/null
    sleep 1

    echo -e "${MAGENTA}Starting rclone mount...${RESET}"

    local ALLOW_OTHER=""
    if grep -q "user_allow_other" /etc/fuse.conf 2>/dev/null; then
        ALLOW_OTHER="--allow-other"
    fi

    nohup rclone mount "$REMOTE":"$REMOTE_PATH" "$MOUNT_PATH" \
        --vfs-cache-mode full \
        --vfs-cache-max-size 20G \
        --vfs-cache-max-age 72h \
        --vfs-read-ahead 256M \
        --vfs-read-chunk-size 64M \
        --vfs-read-chunk-size-limit 2G \
        --buffer-size 512M \
        --dir-cache-time 1000h \
        --poll-interval 60s \
        --timeout 1h \
        --umask 002 \
        --transfers 16 \
        --checkers 16 \
        --tpslimit 10 \
        --drive-chunk-size 64M \
        --fast-list \
        $ALLOW_OTHER \
        --log-level INFO \
        --log-file "$LOG_FILE" \
        > /dev/null 2>&1 &

    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        sleep 2
        if is_mounted; then
            echo -e "${GREEN}Successfully mounted at $MOUNT_PATH${RESET}"
            if timeout 5 ls "$MOUNT_PATH" >/dev/null 2>&1; then
                echo -e "${GREEN}Mount verified - directory is accessible${RESET}"
                return 0
            else
                echo -e "${YELLOW}WARNING: Mounted but directory not yet accessible${RESET}"
            fi
        fi
        retry=$((retry + 1))
        echo -e "${YELLOW}Mount attempt $retry/$MAX_RETRIES...${RESET}"
    done

    echo -e "${RED}ERROR: Failed to mount after $MAX_RETRIES attempts${RESET}"
    echo -e "${CYAN}Check log at: $LOG_FILE${RESET}"
    pkill -f "rclone mount.*$MOUNT_PATH" 2>/dev/null
    return 1
}

# ── Unmount Wrapper ─────────────────────────────────────────────────────────────
unmount_drive() {
    if ! is_mounted; then
        echo -e "${MAGENTA}Not mounted${RESET}"
        return 0
    fi

    echo -e "${MAGENTA}Unmounting Google Drive...${RESET}"
    force_unmount
}

# Status format
show_status() {
    clear
    echo -e "  ${BRIGHT_CYAN_BOLD}══════════════ ${BRIGHT_RED_BOLD}RCLONE STATUS${RESET} ${BRIGHT_CYAN_BOLD}══════════════${RESET}"
    echo

    if is_mounted; then
        MOUNT_STATUS="${GREEN}MOUNTED${RESET}"
    else
        MOUNT_STATUS="${RED}NOT MOUNTED${RESET}"
    fi

    if pgrep -f "rclone mount.*$MOUNT_PATH" >/dev/null; then
        PID=$(pgrep -f "rclone mount.*$MOUNT_PATH" | head -1)
        UPTIME=$(ps -p "$PID" -o etime= 2>/dev/null | xargs)
        PROCESS_STATUS="${GREEN}RUNNING${RESET}"
        PROCESS_INFO="${DIM}(PID:${RESET} ${DIM}${PID}${RESET})"
    else
        PROCESS_STATUS="${RED}NOT RUNNING${RESET}"
        PROCESS_INFO=""
        UPTIME=""
    fi

    if [ -n "$UPTIME" ]; then
        UPTIME_INFO="  ${BRIGHT_YELLOW_BOLD}Uptime:${RESET} ${DIM}${UPTIME}${RESET}"
    fi

    if [ -d "$CACHE_DIR" ]; then
        CACHE_SIZE=$(du -sb "$CACHE_DIR" 2>/dev/null | awk '{print $1}')
        CACHE_FILES=$(find "$CACHE_DIR" -type f 2>/dev/null | wc -l)
        CACHE_SIZE_HR=$(format_bytes ${CACHE_SIZE:-0})
    else
        CACHE_SIZE_HR="0B"
        CACHE_FILES="0"
    fi

    if is_mounted; then
        MOUNT_INFO=$(df -h "$MOUNT_PATH" 2>/dev/null | tail -1)
        SIZE=$(echo "$MOUNT_INFO" | awk '{print $2}')
        USED=$(echo "$MOUNT_INFO" | awk '{print $3}')
        AVAILABLE=$(echo "$MOUNT_INFO" | awk '{print $4}')
        USE_PERCENT=$(echo "$MOUNT_INFO" | awk '{print $5}')
    fi

    echo -e "  ${BRIGHT_YELLOW_BOLD}Mount Status:${RESET} ${MOUNT_STATUS}"
    echo -e "  ${BRIGHT_YELLOW_BOLD}Process:${RESET} ${PROCESS_STATUS} ${PROCESS_INFO}"
    [ -n "$UPTIME_INFO" ] && echo -e "$UPTIME_INFO"
    echo -e "  ${BRIGHT_YELLOW_BOLD}CONFIGURATION:${RESET}"
    echo -e "    ${BRIGHT_CYAN_BOLD}├─${RESET} ${BRIGHT_MAGENTA_BOLD}Remote:${RESET}       ${WHITE}${REMOTE}${RESET}"
    echo -e "    ${BRIGHT_CYAN_BOLD}├─${RESET} ${BRIGHT_MAGENTA_BOLD}Remote Path:${RESET}  ${WHITE}${REMOTE_PATH}${RESET}"
    echo -e "    ${BRIGHT_CYAN_BOLD}└─${RESET} ${BRIGHT_MAGENTA_BOLD}Mount Path:${RESET}   ${WHITE}${MOUNT_PATH}${RESET}"
    echo -e "  ${BRIGHT_YELLOW_BOLD}CACHE:${RESET}"
    echo -e "    ${BRIGHT_CYAN_BOLD}├─${RESET} ${BRIGHT_MAGENTA_BOLD}Size:${RESET}        ${WHITE}${CACHE_SIZE_HR}${RESET}"
    echo -e "    ${BRIGHT_CYAN_BOLD}└─${RESET} ${BRIGHT_MAGENTA_BOLD}Files:${RESET}       ${WHITE}${CACHE_FILES}${RESET}"
    if is_mounted; then
        echo -e "  ${BRIGHT_YELLOW_BOLD}STORAGE:${RESET}"
        echo -e "    ${BRIGHT_CYAN_BOLD}├─${RESET} ${BRIGHT_MAGENTA_BOLD}Size:${RESET}        ${WHITE}${SIZE}${RESET}"
        echo -e "    ${BRIGHT_CYAN_BOLD}├─${RESET} ${BRIGHT_MAGENTA_BOLD}Used:${RESET}        ${WHITE}${USED}${RESET} ${DIM}(${USE_PERCENT})${RESET}"
        echo -e "    ${BRIGHT_CYAN_BOLD}└─${RESET} ${BRIGHT_MAGENTA_BOLD}Available:${RESET}   ${WHITE}${AVAILABLE}${RESET}"
        echo
    fi
}

# ── Restart ─────────────────────────────────────────────────────────────────────
restart_drive() {
    echo -e "${MAGENTA}Restarting rclone mount...${RESET}"
    unmount_drive
    sleep 2
    mount_drive
}

# ── Main ────────────────────────────────────────────────────────────────────────
case "$1" in
    --mount|-m)
        mount_drive ;;
    --unmount|-u)
        unmount_drive ;;
    --status|-s)
        show_status ;;
    --restart|-r)
        restart_drive ;;
    --help|-h)
        echo -e "${CYAN}Usage:${RESET} $0 [OPTION]"
        echo
        echo "Options:"
        echo "  --mount,   -m   Mount Google Drive"
        echo "  --unmount, -u   Unmount Google Drive"
        echo "  --status,  -s   Show mount status"
        echo "  --restart, -r   Restart mount"
        echo "  --help,    -h   Show this help message"
        echo
        echo "Configuration:"
        echo "  Remote:      $REMOTE:$REMOTE_PATH"
        echo "  Mount Path:  $MOUNT_PATH"
        echo "  Log File:    $LOG_FILE"
        ;;
    *)
        echo "Usage: $0 {--mount|--unmount|--status|--restart|--help}"
        echo "Try '$0 --help' for more information."
        exit 1
        ;;
esac
