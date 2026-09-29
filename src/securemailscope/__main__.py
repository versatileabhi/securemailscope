"""
SecureMailScope — Package entry point.

Allows running the CLI as:
    python -m securemailscope [args]
"""

import sys

from securemailscope.cli import main

if __name__ == "__main__":
    sys.exit(main())
