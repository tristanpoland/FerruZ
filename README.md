# FerruZ - DayZ Server Manager

FerruZ is a command-line tool for simple and efficient management of DayZ standalone servers using Docker containers. It provides an easy way to deploy, configure, and maintain multiple DayZ servers on your host machine.

![FerruZ](https://img.shields.io/badge/FerruZ-DayZ%20Server%20Manager-blue)
![Rust](https://img.shields.io/badge/Built%20with-Rust-orange)
![Docker](https://img.shields.io/badge/Docker-Powered-blue)

## Features

- 🚀 **Simple Deployment**: Deploy DayZ servers with a single command
- 🔄 **Server Management**: Start, stop, and restart servers easily
- 📊 **Status Monitoring**: View detailed server information and resource usage
- 📝 **Log Access**: View and follow server logs in real-time
- 🧩 **Mod Support**: Add, remove, and update Steam Workshop mods
- 💾 **Backup & Restore**: Create and restore backups of your server data
- 🔒 **Secure**: Safely store Steam credentials with basic encryption
- 🐚 **Shell Access**: Access an interactive shell inside your server container
- 🧰 **Command Execution**: Execute commands directly within your DayZ server container

## Prerequisites

- Docker (https://docs.docker.com/get-docker/)
- Docker Compose v1 or v2 (https://docs.docker.com/compose/install/)
- A valid Steam account with DayZ purchased
- Sufficient disk space for DayZ server files (~12GB per server)

## Installation

1. Download the latest FerruZ release for your platform from the [Releases page](https://github.com/tristanpoland/ferruz/releases).

2. Make the binary executable:
   ```bash
   chmod +x ferruz
   ```

3. Move it to a directory in your PATH:
   ```bash
   sudo mv ferruz /usr/local/bin/
   ```

## Quick Start

### Configure Steam Credentials

Before deploying a server, you'll need to configure your Steam credentials:

```bash
ferruz config
```

### Deploy Your First Server

Interactive mode (recommended):

```bash
ferruz deploy
```

Or with specific parameters:

```bash
ferruz deploy --name my-server --port 2302 --max-players 60 --location chernarusplus
```

### Start, Stop and Restart Servers

```bash
# Start a server
ferruz start my-server

# Stop a server
ferruz stop my-server

# Restart a server
ferruz restart my-server
```

### List All Servers

```bash
ferruz list
```

### View Server Logs

```bash
# Show the last 100 lines of logs
ferruz logs my-server

# Follow logs in real-time
ferruz logs my-server --follow
```

## Server Management Commands

### View Server Status

```bash
ferruz status my-server
```

### Update Server

```bash
# Update server
ferruz update my-server

# Update with file validation (fix corrupted files)
ferruz update my-server --validate
```

### Manage Mods

```bash
# List installed mods
ferruz mods list my-server

# Add mods (using Steam Workshop IDs)
ferruz mods add my-server 1559212036,1590841260

# Remove mods
ferruz mods remove my-server 1559212036

# Update all installed mods
ferruz mods update my-server
```

### Access Server Shell

```bash
ferruz shell my-server
```

### Execute Commands

```bash
ferruz execute my-server ls -la
```

### Backup and Restore

```bash
# Create a backup
ferruz backup my-server

# Create a backup with custom output directory
ferruz backup my-server --output /path/to/backup/dir

# Restore a backup
ferruz restore my-server /path/to/backup/file.tar.gz
```

## Advanced Configuration

### Server Configuration Files

Server config files are stored in the server data directory:
```
~/.local/share/ferruz/servers/data/dayz-server-[NAME]/
```

The main configuration file is `serverDZ.cfg`. Edit this file to customize server settings beyond what's available through the CLI.

### Custom Server Config

You can provide a custom server configuration when deploying:

```bash
ferruz deploy --name my-server --config /path/to/custom/serverDZ.cfg
```

## Command Reference

```
USAGE:
    ferruz [COMMAND]

COMMANDS:
    deploy, d          Deploy a new DayZ server
    start, s           Start an existing DayZ server
    stop, down         Stop a running DayZ server
    restart, r         Restart a running DayZ server
    list, ls           List all DayZ servers
    config, cfg        Configure Steam credentials
    logs, l            View or follow server logs
    execute, exec      Execute a command on the server
    status, stat       Show server status
    update, up         Update the server
    mods, mod          Manage server mods
    shell, sh          Access an interactive shell in the server container
    backup, bkp        Create a backup of server data
    restore, rest      Restore a backup
    help               Print this message or the help of the given subcommand(s)
```

## Data Storage

FerruZ stores its configuration and server data in the following locations:

- **Config file**: `~/.local/share/ferruz/config.json`
- **Server files**: `~/.local/share/ferruz/servers/data/dayz-server-[NAME]/`
- **Backups**: `~/.local/share/ferruz/backups/`

## Tips for Server Operators

1. **Server Performance**: The DayZ server can be resource-intensive. Allocate sufficient CPU cores and RAM for optimal performance.

2. **First Start**: The initial server startup may take some time as it downloads DayZ server files from Steam.

3. **Port Forwarding**: To make your server publicly accessible, forward the following ports in your router:
   - Server Port (Default: 2302/UDP)
   - Port+1 to Port+4 (2303-2306/UDP)
   - Port+14714 (27016/UDP)

4. **Regular Backups**: Set up regular backups of your server to prevent data loss.

5. **Workshop Mods**: When adding mods, ensure they are compatible with each other.

## Troubleshooting

### Server Won't Start
- Check if Docker service is running
- Ensure you have enough disk space
- Verify port availability (ports might be in use by another service)
- Check the logs with `ferruz logs [server-name]` for detailed error messages

### Poor Server Performance
- Check CPU and memory usage with `ferruz status [server-name]`
- Consider reducing the number of mods or players
- Ensure your host system has adequate resources

### Connection Issues
- Verify port forwarding configuration in your router
- Check firewall settings
- Test connectivity with tools like netcat

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with Rust and Docker
- Uses the ich777/steamcmd Docker image for DayZ server deployment

---

Created with ❤️ by Tristan Polandit