"""
smb-pyfuse CLI
==============

Mount or unmount an SMB share via FUSE.

Mount usage::

    python main.py mount <mountpoint> <server> <share> [options]

Unmount usage::

    python main.py unmount <mountpoint>
"""

from __future__ import annotations

import argparse
import logging
import sys

from smb_pyfuse import mount, unmount


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smb-pyfuse",
        description="Mount an SMB share via FUSE",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- mount sub-command ------------------------------------------------
    mp = sub.add_parser("mount", help="Mount an SMB share")
    mp.add_argument("mountpoint",  help="Local directory to mount the share at")
    mp.add_argument("server",      help="SMB server hostname or IP address")
    mp.add_argument("share",       help="Share name (without backslashes)")
    mp.add_argument("-u", "--username",          default=None)
    mp.add_argument("-p", "--password",          default=None)
    mp.add_argument("--port",                    type=int, default=445)
    mp.add_argument("--kerberos",                action="store_true",
                    help="Authenticate with the current Kerberos TGT")
    mp.add_argument("--encrypt",                 action="store_true", default=None,
                    help="Request SMB3 encryption")
    mp.add_argument("--connection-timeout",      type=int, default=60,
                    dest="connection_timeout")
    mp.add_argument("-f", "--foreground",        action="store_true",
                    help="Run in foreground (block until unmounted)")
    mp.add_argument("--allow-other",             action="store_true",
                    dest="allow_other",
                    help="Allow other users to access the mount")
    mp.add_argument("--allow-root",              action="store_true",
                    dest="allow_root",
                    help="Allow root to access the mount")
    mp.add_argument("-v", "--verbose",           action="store_true")

    # ---- unmount sub-command ----------------------------------------------
    up = sub.add_parser("unmount", help="Unmount a FUSE filesystem")
    up.add_argument("mountpoint", help="Directory to unmount")

    return parser


def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if getattr(args, "verbose", False):
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING,
                            format="%(levelname)s: %(message)s")

    if args.command == "mount":
        try:
            mount(
                mountpoint         = args.mountpoint,
                server             = args.server,
                share              = args.share,
                username           = args.username,
                password           = args.password,
                port               = args.port,
                kerberos           = args.kerberos,
                encrypt            = True if args.encrypt else None,
                connection_timeout = args.connection_timeout,
                foreground         = args.foreground,
                allow_other        = args.allow_other,
                allow_root         = args.allow_root,
            )
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "unmount":
        try:
            unmount(args.mountpoint)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
