
# SmartLight Backup Agent

Home Assistant OS add-on for automated, encrypted backups to SmartLight Backup Manager.

## Features

- Automatic backup scheduling controlled by SmartLight server.
- Secure communication with SmartLight Backup Manager.
- Resumable, chunk-based uploads.
- SHA256 integrity verification.
- Automatic recovery after Home Assistant or network restarts.
- Persistent local upload queue.

## Configuration

| Option | Description |
|---|---|
| client_code | SmartLight client code |
| api_key | Client API key |
| server_url | Backup Manager URL |
| log_level | Logging verbosity |

## Installation

Add the SmartLight repository to Home Assistant Add-on Store.

https://github.com/klepas7/smartlight-ha-backup-agent
