# smb-pyfuse

Mount SMB/CIFS shares as local directories using FUSE.

Built on top of [smbprotocol](https://github.com/jborean93/smbprotocol) and [fuse-python](https://github.com/libfuse/python-fuse), `smb-pyfuse` exposes a remote SMB share as a regular filesystem — supporting reads, writes, directory listing, symlinks, and more.

## Features

- Mount any SMB2/SMB3 share as a local directory
- Username/password and Kerberos authentication
- Optional SMB3 encryption
- Foreground and background (daemon) modes
- `allow_other` / `allow_root` FUSE mount options
- Programmatic Python API (`mount`, `unmount`, `SmbFuseFS`)

## Supported FUSE Operations

| Operation | Description |
|-----------|-------------|
| `getattr` | File/directory metadata (stat) |
| `readdir` | List directory contents |
| `mkdir` / `rmdir` | Create / remove directories |
| `rename` | Rename files or directories |
| `unlink` | Delete a file |
| `mknod` | Create a new regular file |
| `open` / `read` / `write` / `release` | File I/O |
| `truncate` / `ftruncate` | Truncate a file |
| `flush` / `fsync` | Flush / sync file data |
| `symlink` / `readlink` / `link` | Symbolic and hard links |
| `utime` | Update access/modification times |
| `chmod` / `chown` | No-op (silently succeeds for tool compatibility) |
| `access` | Existence check via stat |
| `statfs` | Returns sensible defaults |

## Prerequisites

### System Dependencies

```bash
sudo apt install libkrb5-dev build-essential python3-dev
```

### FUSE

FUSE must be available on the host:

```bash
# Debian / Ubuntu
sudo apt install fuse3 libfuse-dev

# To allow non-root users to use allow_other:
# Uncomment 'user_allow_other' in /etc/fuse.conf
```

## Installation

```bash
# Clone the repo
git clone https://github.com/<your-org>/smb-pyfuse.git
cd smb-pyfuse

# Install with uv (recommended)
uv sync --frozen

# Or with pip
pip install .
```

## Usage

### CLI

**Mount** a share (foreground mode):

```bash
uv run main.py mount /mnt/smb myserver.example.com myshare -u 'DOMAIN\user' -p 'password' -f
```

**Mount** with Kerberos (requires a valid TGT in the credential cache):

```bash
kinit user@REALM
uv run main.py mount /mnt/smb myserver.example.com myshare --kerberos -f
```

**Mount** in the background (daemon mode):

```bash
uv run main.py mount /mnt/smb myserver.example.com myshare -u user -p pass
```

**Unmount**:

```bash
uv run main.py unmount /mnt/smb
```

### CLI Options

```
positional arguments:
  mountpoint            Local directory to mount the share at
  server                SMB server hostname or IP address
  share                 Share name (without backslashes)

options:
  -u, --username        SMB username
  -p, --password        SMB password
  --port                SMB TCP port (default: 445)
  --kerberos            Authenticate with Kerberos TGT
  --encrypt             Request SMB3 encryption
  --connection-timeout  TCP connection timeout in seconds (default: 60)
  -f, --foreground      Run in foreground (block until unmounted)
  --allow-other         Allow other users to access the mount
  --allow-root          Allow root to access the mount
  -v, --verbose         Enable debug logging
```

### Python API

```python
from smb_pyfuse import mount, unmount

# Mount (blocks in foreground mode)
mount(
    mountpoint="/mnt/smb",
    server="myserver.example.com",
    share="myshare",
    username="alice",
    password="s3cr3t",
    foreground=True,
)

# Unmount
unmount("/mnt/smb")
```

Or use the filesystem class directly:

```python
from smb_pyfuse import SmbFuseFS

fs = SmbFuseFS(
    server="myserver.example.com",
    share="myshare",
    username="alice",
    password="s3cr3t",
)
fs.fuse_args.mountpoint = "/mnt/smb"
fs.fuse_args.add("allow_other")
fs.main()
```

## License

[MIT](LICENSE)
