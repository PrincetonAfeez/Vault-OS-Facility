"""facility.bootstrap - Bootstrap the Vault OS Facility package"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_SUBPROJECTS = ("Access", "Devices", "Events", "Invites", "Personnel", "Vault")


