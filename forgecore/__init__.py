"""ForgeCore OS - a local operator console with an encrypted vault.

This package backs the six subsystems named on the startup banner:

* :mod:`forgecore.console`   - Founder Console / terminal output
* :mod:`forgecore.dashboard` - Daily Dashboard metrics
* :mod:`forgecore.agents`    - Agent Nexus hub registry
* :mod:`forgecore.uploads`   - Upload panel file intake
* :mod:`forgecore.vault`     - Encrypted Vault (AES-256-GCM)

Importing this package has no side effects: nothing is printed, no files are
created and no directories are touched until a command actually runs.
"""

from __future__ import annotations

__all__ = ["__version__", "APP_NAME"]

__version__ = "1.0.0"
APP_NAME = "ForgeCore OS"
