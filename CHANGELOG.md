# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.1] - 2026-04-16

### Fixed
- ZSH theme and config files not being copied - script now uses script directory instead of `~/initium` for theme/config paths
- Unquoted `$pid` variable in spinner functions (`kill`, `wait`, `spinner` calls)
- Redundant `2>&1` redirect in tmux source-file check (`&>` already covers both streams)
- Duplicate `# Ubuntu drivers` comment in driver installation function

### Removed
- Stale WORK_DIR variable (was referencing non-existent `~/initium` directory)
- Scripts directory copy logic (directory doesn't exist in repo)
- Stale blank sections from removed features (cloud storage, desktop environment)

### Notes
- Configuration variables `BACKUP_DIR`, `CONFIG_DIR`, `LOG_FILE`, `MAX_RETRIES`, `TIMEOUT_SECONDS` remain defined for CLI argument support but are not yet consumed by functions
- Docker repository codename is hardcoded to `noble` (Ubuntu 24.04)

## [2.3.0] - 2026-04-16

### Removed
- Cloud storage (Rclone) configuration functionality
- GitHub authentication and SSH key management
- Git global configuration
- Desktop environment installation (XFCE4)

### Focus
- Streamlined to core system setup, hardening, and developer tooling

## [2.2.0] - 2026-04-16

### Changed
- Initial cleanup of identity management and desktop environment features

## [2.1.0] - 2026-04-15

### Added
- Original comprehensive system setup script
- Interactive Ubuntu system configuration
- Docker and Docker Compose installation
- Node.js via NVM
- Zsh with Oh My Zsh, syntax highlighting, autosuggestions
- Tmux with custom configuration
- Powerline setup
- Custom Vim configuration
- SSH hardening
- Driver and firmware installation
- Custom MOTD
- User configuration file deployment

[2.4.1]: https://github.com/whonixnetworks/initium/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/whonixnetworks/initium/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/whonixnetworks/initium/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/whonixnetworks/initium/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/whonixnetworks/initium/releases/tag/v2.1.0