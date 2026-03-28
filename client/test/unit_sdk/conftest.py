from __future__ import annotations

import sys
from pathlib import Path


# Ensure imports like `tools.azt_sdk...` resolve in tests.
CLIENT_ROOT = Path(__file__).resolve().parents[2]
if str(CLIENT_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_ROOT))
