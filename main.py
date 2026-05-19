"""
smb-pyfuse CLI
==============

Mount or unmount an SMB share via FUSE.

Mount usage::

    python main.py mount <mountpoint> <server> <share> [options]

Unmount usage::

    python main.py unmount <mountpoint>
"""

from smb_pyfuse.__main__ import main

if __name__ == "__main__":
    main()
