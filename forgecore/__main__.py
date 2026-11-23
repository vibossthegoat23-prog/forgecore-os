"""Allow ``python -m forgecore`` as an alternative to the ``forgecore`` script."""

from __future__ import annotations

import sys

from forgecore.cli import main

if __name__ == "__main__":
    sys.exit(main())
