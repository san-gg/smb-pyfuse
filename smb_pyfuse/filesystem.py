"""
Core FUSE filesystem implementation backed by smbclient.

All FUSE I/O operations are forwarded to the ``smbclient`` module from the
``smbprotocol`` package.  The filesystem is single-threaded by default
because an smbclient session is not safe to share across threads without
additional locking.
"""

from __future__ import annotations

import errno
import logging
import os
import stat as _stat
import time
from typing import Optional

import sys

import fuse
import smbclient

# fuse-python API version declaration – must be set before importing
# anything else from the fuse module.
fuse.fuse_python_api = (0, 2)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _smb_errno(exc: OSError) -> int:
    """Return the errno carried by *exc*, falling back to EIO."""
    return exc.errno if exc.errno else errno.EIO


def _flags_to_mode(flags: int) -> str:
    """Convert POSIX ``open(2)`` flags to a Python/smbclient mode string."""
    access = flags & os.O_ACCMODE  # 0 = RDONLY, 1 = WRONLY, 2 = RDWR
    is_append = bool(flags & os.O_APPEND)
    is_creat  = bool(flags & os.O_CREAT)
    is_trunc  = bool(flags & os.O_TRUNC)

    if access == os.O_RDONLY:
        return "rb"

    if access == os.O_WRONLY:
        if is_append:
            return "ab"
        if is_creat or is_trunc:
            return "wb"
        return "r+b"  # write to existing without truncation

    # O_RDWR
    if is_creat or is_trunc:
        return "w+b"
    return "r+b"


# Maximum value that fits in a C signed long (used by fuse.Stat fields).
_C_LONG_MAX = (2 ** (8 * 8 - 1)) - 1 if sys.maxsize > 2**32 else (2 ** 31) - 1


def _clamp(value: int, lo: int = 0, hi: int = _C_LONG_MAX) -> int:
    """Clamp *value* so it fits in a C long (avoids OverflowError)."""
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _stat_from_smb(smb_st) -> fuse.Stat:
    """Translate an ``SMBStatResult`` to a ``fuse.Stat`` object."""
    st = fuse.Stat()
    st.st_mode  = smb_st.st_mode
    st.st_ino   = _clamp(smb_st.st_ino)
    st.st_dev   = _clamp(smb_st.st_dev)
    st.st_nlink = max(smb_st.st_nlink, 1)
    st.st_uid   = os.getuid()
    st.st_gid   = os.getgid()
    st.st_size  = smb_st.st_size
    st.st_atime = int(smb_st.st_atime)
    st.st_mtime = int(smb_st.st_mtime)
    st.st_ctime = int(smb_st.st_ctime)
    return st


# ---------------------------------------------------------------------------
# Per-open-file handle (used as fuse-python ``file_class``)
# ---------------------------------------------------------------------------


class _SmbFileHandle:
    """
    Wraps a single open SMB file.

    fuse-python instantiates this class for every ``open()`` / ``create()``
    call.  Subsequent ``read``, ``write``, ``release``, … calls are
    dispatched to the instance rather than to the filesystem class, which
    means no path-based look-up is needed after the file is opened.

    The class attribute ``_fs`` is patched to the owning :class:`SmbFuseFS`
    instance at construction time (via a dynamically created subclass).
    """

    direct_io  = False
    keep_cache = False

    # Filled in by SmbFuseFS.__init__ via a per-instance subclass
    _fs: "SmbFuseFS"

    # ------------------------------------------------------------------
    # Construction / destruction
    # ------------------------------------------------------------------

    def __init__(self, path: str, flags: int, *mode: int) -> None:
        smb_path  = self._fs._smb_path(path)
        open_mode = _flags_to_mode(flags)
        try:
            # share_access='rwd' allows concurrent readers/writers on the
            # same share, which is the typical SMB expectation.
            self._fh   = smbclient.open_file(smb_path, mode=open_mode,
                                             share_access="rwd",
                                             **self._fs._conn_opts)
            self._path = smb_path
        except OSError as exc:
            raise IOError(_smb_errno(exc), str(exc)) from exc

    # ------------------------------------------------------------------
    # Data operations
    # ------------------------------------------------------------------

    def read(self, size: int, offset: int) -> bytes:
        try:
            self._fh.seek(offset)
            return self._fh.read(size)
        except OSError as exc:
            return -_smb_errno(exc)

    def write(self, buf: bytes, offset: int) -> int:
        try:
            self._fh.seek(offset)
            return self._fh.write(buf)
        except OSError as exc:
            return -_smb_errno(exc)

    def release(self, flags: int) -> int:
        try:
            self._fh.close()
        except OSError:
            pass
        return 0

    def flush(self) -> int:
        try:
            self._fh.flush()
        except OSError as exc:
            return -_smb_errno(exc)
        return 0

    def fsync(self, is_fdatasync: int) -> int:
        # SMB does not distinguish data-sync from full sync; flush suffices.
        return self.flush()

    # ------------------------------------------------------------------
    # Per-handle metadata
    # ------------------------------------------------------------------

    def fgetattr(self):
        try:
            return _stat_from_smb(smbclient.stat(self._path, **self._fs._conn_opts))
        except OSError as exc:
            return -_smb_errno(exc)

    def ftruncate(self, size: int) -> int:
        try:
            self._fh.seek(0)
            self._fh.truncate(size)
        except OSError as exc:
            return -_smb_errno(exc)
        return 0

    # ------------------------------------------------------------------
    # Advisory locking (not supported over SMB via FUSE)
    # ------------------------------------------------------------------

    def lock(self, cmd, owner, **kw) -> int:  # noqa: ANN001
        return -errno.ENOSYS


# ---------------------------------------------------------------------------
# Filesystem class
# ---------------------------------------------------------------------------


class SmbFuseFS(fuse.Fuse):
    """
    FUSE filesystem that proxies all I/O through :mod:`smbclient`.

    Parameters
    ----------
    server:
        Hostname or IP address of the SMB server.
    share:
        Share name on the server (without leading backslashes).
    username:
        Account name for authentication.  ``None`` uses the current OS user
        (relevant for Kerberos / NTLM pass-through).
    password:
        Plaintext password.  ``None`` for Kerberos or anonymous access.
    port:
        TCP port of the SMB service (default 445).
    kerberos:
        When ``True`` the session is authenticated with Kerberos using the
        current TGT; ``username`` / ``password`` are ignored.
    encrypt:
        Request SMB encryption.  ``None`` lets the server decide.
    connection_timeout:
        TCP connection timeout in seconds.
    **fuse_kwargs:
        Keyword arguments forwarded verbatim to :class:`fuse.Fuse.__init__`,
        e.g. ``version``, ``usage``, ``dash_s_do``.

    Usage example::

        fs = SmbFuseFS(server="nas.local", share="data",
                       username="alice", password="s3cr3t")
        fs.fuse_args.mountpoint = "/mnt/smb"
        fs.fuse_args.add("allow_other")
        fs.main()   # returns once FUSE has forked (background mode)
    """

    def __init__(
        self,
        server: str,
        share: str,
        *,
        username: Optional[str]  = None,
        password: Optional[str]  = None,
        port: int                = 445,
        kerberos: bool           = False,
        encrypt: Optional[bool]  = None,
        connection_timeout: int  = 60,
        **fuse_kwargs,
    ) -> None:
        super().__init__(**fuse_kwargs)

        self.server = server
        self.share  = share

        # Single-threaded: one SMB session per process.
        self.multithreaded = False

        # Configure session-level options via ClientConfig.
        if kerberos:
            smbclient.ClientConfig(auth_protocol="kerberos")
        if encrypt is not None:
            smbclient.ClientConfig(require_secure_negotiate=encrypt)

        # These kwargs are accepted by every smbclient high-level function
        # and are used to implicitly create / look up the cached session.
        self._conn_opts: dict = dict(
            username           = username,
            password           = password,
            port               = port,
            connection_timeout = connection_timeout,
        )

        # Create a per-instance file-handle class so that _fs points to
        # this specific SmbFuseFS object (avoids global state).
        _this = self

        class _BoundFileHandle(_SmbFileHandle):
            _fs = _this

        self.file_class = _BoundFileHandle

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _smb_path(self, fuse_path: str) -> str:
        """
        Convert a FUSE absolute path to an SMB UNC path.

        ``/``          →  ``\\\\server\\share``
        ``/docs/a.txt``  →  ``\\\\server\\share\\docs\\a.txt``
        """
        base = f"\\\\{self.server}\\{self.share}"
        if fuse_path in ("", "/"):
            return base
        return base + fuse_path.replace("/", "\\")

    # ------------------------------------------------------------------
    # Metadata / directory operations
    # ------------------------------------------------------------------

    def getattr(self, path: str):
        try:
            return _stat_from_smb(smbclient.stat(self._smb_path(path), **self._conn_opts))
        except OSError as exc:
            return -_smb_errno(exc)

    def readdir(self, path: str, offset: int):
        yield fuse.Direntry(".")
        yield fuse.Direntry("..")
        try:
            for entry in smbclient.scandir(self._smb_path(path), **self._conn_opts):
                yield fuse.Direntry(entry.name)
        except OSError as exc:
            log.error("readdir %s: %s", path, exc)

    def mkdir(self, path: str, mode: int) -> int:
        try:
            smbclient.mkdir(self._smb_path(path), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def rmdir(self, path: str) -> int:
        try:
            smbclient.rmdir(self._smb_path(path), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def rename(self, old: str, new: str) -> int:
        try:
            smbclient.rename(self._smb_path(old), self._smb_path(new), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def unlink(self, path: str) -> int:
        try:
            smbclient.remove(self._smb_path(path), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def mknod(self, path: str, mode: int, dev: int) -> int:
        """Create a new regular file (device nodes are not supported over SMB)."""
        if not _stat.S_ISREG(mode):
            return -errno.EPERM
        try:
            with smbclient.open_file(self._smb_path(path), mode="wb", **self._conn_opts):
                pass  # create empty file
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    # ------------------------------------------------------------------
    # Symbolic / hard links
    # ------------------------------------------------------------------

    def symlink(self, target: str, name: str) -> int:
        try:
            smbclient.symlink(target, self._smb_path(name), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def readlink(self, path: str):
        try:
            return smbclient.readlink(self._smb_path(path), **self._conn_opts)
        except OSError as exc:
            return -_smb_errno(exc)

    def link(self, target: str, name: str) -> int:
        try:
            smbclient.link(self._smb_path(target), self._smb_path(name), **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    # ------------------------------------------------------------------
    # Permissions and timestamps
    # ------------------------------------------------------------------

    def chmod(self, path: str, mode: int) -> int:
        # smbclient has no chmod; silently succeed so cp/rsync don't fail.
        return 0

    def chown(self, path: str, uid: int, gid: int) -> int:
        # SMB ownership is managed server-side; silently succeed so that
        # standard tools (e.g. cp --preserve) do not fail.
        return 0

    def truncate(self, path: str, length: int) -> int:
        try:
            smbclient.truncate(self._smb_path(path), length, **self._conn_opts)
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    def utime(self, path: str, times) -> int:
        """Update access and modification times via ``smbclient.utime``."""
        try:
            if hasattr(smbclient, "utime"):
                ts = times if times is not None else (time.time(), time.time())
                smbclient.utime(self._smb_path(path), ts, **self._conn_opts)
            # If smbclient.utime is unavailable we accept silently; most SMB
            # servers apply the current time on write anyway.
            return 0
        except OSError as exc:
            return -_smb_errno(exc)

    # ------------------------------------------------------------------
    # Access check
    # ------------------------------------------------------------------

    def access(self, path: str, mode: int) -> int:
        """Check path exists via stat (smbclient has no access())."""
        try:
            smbclient.stat(self._smb_path(path), **self._conn_opts)
        except OSError:
            return -errno.EACCES
        return 0

    # ------------------------------------------------------------------
    # Filesystem statistics
    # ------------------------------------------------------------------

    def statfs(self):
        # smbclient has no statvfs; return sensible defaults.
        st = fuse.StatVfs()
        st.f_bsize   = 4096
        st.f_frsize  = 4096
        st.f_namemax = 255
        return st
