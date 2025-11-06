# Whonix Initium

<p align="center">
  <img src="/initium.png" alt="Initium Logo" width="200"/>
</p>

<p align="center">
  <b>Initium</b> <br/>
  <i>/ɪˈnɪtiəm/</i> <br/>
  <small><i>noun</i></small> <br/>
  <i>"the beginning;"</i>
</p>

A TUI-based bash script to streamline the setup and management of Debian/Ubuntu servers for home lab environments.

## What It Does

This script provides a user-friendly text-based interface (TUI) to perform a variety of system administration tasks. Instead of a fully automated script, it gives you a menu of options so you can choose exactly what you want to do.

Its main functions include:
- **System Updates** - Updates package lists and upgrades existing packages.
- **Package Installation** - Install common packages like Docker, developer tools, and other base utilities.
- **System Settings** - Change the hostname, harden SSH, configure the firewall (UFW), manage users and SSH keys, and set the timezone.
- **Network Configuration** - Set a static IP address or change DNS servers.
- **MOTD Creation** - Generate a custom MOTD with figlet.
- **Maintenance** - Clean up the system and prune Docker resources.
- **Alias and Git Configuration** - Install a set of useful shell aliases and configure your Git identity.

> [!WARNING]
> The SSH hardening option will disable password authentication. Make sure you have SSH keys ready before using this feature, otherwise you could get locked out of your server.

## Responsive Design

The TUI now dynamically adjusts to your terminal size, making it usable on various devices:
- **Laptops/Desktops**: Full-size interface with optimal spacing
- **Mobile Devices (Android/iOS terminals)**: Automatically scales down for smaller screens
- **Remote Sessions**: Adapts to different terminal dimensions

The interface will:
- Scale menus and dialog boxes based on terminal dimensions
- Maintain readability on both large and small screens
- Provide appropriate spacing and layout for different aspect ratios
- Cap maximum sizes for better usability on very large terminals

## Quick Start

1. Download the script:
```shell
git clone https://github.com/whonixnetworks/initium.git && chmod +x initium/init.sh
```

2. Run it:
```shell
cd initium
./initium/init.sh
```

3. Use the arrow keys to navigate the menus and select the tasks you want to perform.

**Lazy Commands**
```shell
git clone https://github.com/whonixnetworks/initium.git && chmod +x initium/init.sh && cd initium && ./init.sh
```

## What Gets Installed

The script can install the following packages, grouped by category:

### Core Packages

- **Base:** `git`, `gh`, `btop`, `wireguard`, `tmux`, `neofetch`, `mc`, `htop`, `iotop`, `iftop`, `wget`, `curl`, `jq`, `nano`, `ufw`, `figlet`, and more.
- **Docker:** `docker.io` and `docker-compose-v2`.
- **Development:** `python3`, `pip`, `npm`, `speedtest-cli`.

### SSH Configuration

The script provides several options for managing SSH:

- **Harden SSH** - Disables password authentication and root login with a password.
- **Manage SSH Keys** - Easily add your public SSH key to the authorized_keys file.
- **Change SSH Port** - Change the default SSH port from 22 to something else.
- **Install Fail2ban** - Installs Fail2ban for brute-force attack protection.

### Handy Aliases Added

A separate `alias` file is included which can be sourced by your shell. It contains many shortcuts, including:

- **System:** `reload`, `reboot`, `shutdown`, `c` (clear), `sstat` (detailed system status), `update` (system update).
- **Git:** `gadd`, `gcmt`, `gpush`, `gpull`, `gstat` (detailed git status), `gpsh` (interactive push).
- **Docker:** `dcu` (up), `dcd` (down), `dcr` (restart), `dcl` (logs), `dps` (ps).
- And many more for file management and docker-compose.

## Requirements

- Debian or Ubuntu server (tested on Ubuntu 22.04 LTS and Debian 12)
- Sudo privileges
- Internet connection

## How It Works

The script uses `whiptail` to create a simple and intuitive TUI. It's organized into submenus for different categories of tasks:

1.  **System Updates**
2.  **Install Packages**
3.  **Create MOTD**
4.  **System Settings**
5.  **Network Settings**
6.  **Maintenance**
7.  **Others**

You can navigate through these menus to perform tasks. The script executes the corresponding commands in the background, showing progress bars for longer operations.

## After Setup

- If you harden SSH, you'll need to use SSH keys to connect to your server.
- If you install Docker, your user will be added to the `docker` group, allowing you to run Docker commands without `sudo` (after you log out and back in).
- If you configure aliases, they will be available in new shell sessions.

## Safety Features

- **Root Check** - Prevents the script from being run as the root user.
- **Sudo Verification** - Ensures the user has sudo privileges before starting.
- **Configuration Backups** - Creates backups of critical files like `/etc/ssh/sshd_config` before modifying them.
- **Clear Warnings** - Provides clear warnings for potentially risky operations like hardening SSH or changing the SSH port.

## Customization

The script itself is the customization tool. You can pick and choose which actions to perform from the menu. If you want to change the list of packages to be installed, you can edit the `init.sh` script directly. The aliases can be customized by editing the `alias` file.

## Troubleshooting

**Can't SSH after hardening**: Make sure you have added your public SSH key via the `Manage SSH Keys` menu before hardening. If you get locked out, you will need to access your server through a console or recovery mode to fix it.

**Docker commands need sudo**: Log out and back in after installing Docker. This is required for the group changes to take effect.

**Aliases not working**: Make sure you have run the `Configure Aliases` option from the `Others` menu. You may also need to start a new shell session or source your `.bashrc` or `.zshrc` file.

> [!NOTE]
> Always test in a non-production environment first.

## Contributing

Found a bug or want to add something? Feel free to open an issue or submit a pull request.

## License

This script is provided as-is. Use at your own risk.






















































































































































































