#!/usr/bin/env python3
"""ForgeCore OS entry point.

Run ``python3 main.py`` or install the package and use ``forgecore``.
Importing this module prints nothing; the console only starts inside
``if __name__ == "__main__"``.
"""

from __future__ import annotations

import sys

from forgecore.cli import main

if __name__ == "__main__":
    sys.exit(main())
