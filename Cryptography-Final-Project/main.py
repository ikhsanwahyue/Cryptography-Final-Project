#!/usr/bin/env python3
"""
LexVault - Forensic Evidence Custody & Anti-Tamper Archival System
Standard Compliance: ISO/IEC 27037 Digital Chain of Custody
Entrypoint Bootstrap (`main.py`)
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from ui.app_window import LexVaultApp


def main() -> None:
    app = LexVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()

