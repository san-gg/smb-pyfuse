"""
smb_pyfuse – FUSE filesystem backed by smbclient
=================================================

Public API::

    from smb_pyfuse import SmbFuseFS, mount, unmount

Mount example (programmatic)::

    from smb_pyfuse import mount

    # Returns once the FUSE daemon has forked into the background.
    mount(
        mountpoint="/mnt/nas",
        server="nas.example.com",
        share="data",
        username="alice",
        password="s3cr3t",
    )

Mount example with Kerberos (ticket must already exist)::

    mount(
        mountpoint="/mnt/nas",
        server="nas.example.com",
        share="data",
        kerberos=True,
    )

Mount in foreground (blocks until unmounted)::

    mount("/mnt/nas", "nas.example.com", "data", foreground=True)

Direct filesystem object::

    from smb_pyfuse import SmbFuseFS
    import fuse

    fs = SmbFuseFS(server="nas.example.com", share="data",
                   username="alice", password="s3cr3t")
    fs.fuse_args.mountpoint = "/mnt/nas"
    fs.fuse_args.add("allow_other")
    fs.main()
"""

from __future__ import annotations

import os
import subprocess
from typing import Optional

from .filesystem import SmbFuseFS

__all__ = ["SmbFuseFS", "mount", "unmount"]
__version__ = "0.1.0"


def mount(
    mountpoint: str,
    server: str,
    share: str,
    *,
    username: Optional[str]  = None,
    password: Optional[str]  = None,
    port: int                = 445,
    kerberos: bool           = False,
    encrypt: Optional[bool]  = None,
    connection_timeout: int  = 60,
    foreground: bool         = False,
    allow_other: bool        = False,
    allow_root: bool         = False,
) -> None:
    """
    Mount an SMB share at *mountpoint*.

    By default the FUSE daemon runs in the **background** (the kernel module
    forks the daemon and this function returns).  Pass ``foreground=True`` to
    block until the filesystem is unmounted.

    Parameters
    ----------
    mountpoint:
        Local directory where the share will appear.
    server:
        Hostname or IP of the SMB server.
    share:
        Share name (without backslashes).
    username:
        SMB account name.
    password:
        SMB password.
    port:
        SMB TCP port (default 445).
    kerberos:
        Authenticate with the current Kerberos TGT.
    encrypt:
        Request SMB3 encryption.  ``None`` lets the server decide.
    connection_timeout:
        TCP connection timeout in seconds.
    foreground:
        When ``True`` the call blocks until the filesystem is unmounted.
    allow_other:
        Add the ``allow_other`` FUSE mount option (requires
        ``user_allow_other`` in ``/etc/fuse.conf``).
    allow_root:
        Add the ``allow_root`` FUSE mount option.

    Raises
    ------
    RuntimeError
        If *mountpoint* does not exist or is not a directory.
    """
    mountpoint = os.path.realpath(mountpoint)
    if not os.path.isdir(mountpoint):
        raise RuntimeError(f"Mount point does not exist or is not a directory: {mountpoint!r}")

    fs = SmbFuseFS(
        server             = server,
        share              = share,
        username           = username,
        password           = password,
        port               = port,
        kerberos           = kerberos,
        encrypt            = encrypt,
        connection_timeout = connection_timeout,
    )

    fs.fuse_args.mountpoint = mountpoint

    if foreground:
        fs.fuse_args.setmod("foreground")
    if allow_other:
        fs.fuse_args.add("allow_other")
    if allow_root:
        fs.fuse_args.add("allow_root")

    fs.main()


def unmount(mountpoint: str) -> None:
    """
    Unmount a previously mounted FUSE filesystem.

    Tries ``fusermount3 -u`` first, then falls back to ``fusermount -u``,
    and finally to ``umount`` (which typically requires root).

    Parameters
    ----------
    mountpoint:
        The directory passed to :func:`mount`.

    Raises
    ------
    RuntimeError
        If the unmount fails after all attempts.
    """
    mountpoint = os.path.realpath(mountpoint)
    candidates = [
        ["fusermount3", "-u", mountpoint],
        ["fusermount",  "-u", mountpoint],
        ["umount",             mountpoint],
    ]
    for cmd in candidates:
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return
        except FileNotFoundError:
            continue  # tool not installed
        except subprocess.CalledProcessError:
            continue  # tool failed – try next

    raise RuntimeError(f"Could not unmount {mountpoint!r}: all unmount commands failed")
