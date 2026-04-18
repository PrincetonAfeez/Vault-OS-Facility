"""facility.bootstrap - Bootstrap the Vault OS Facility package"""

# Enable post-runtime type hints by allowing forward references and type annotations as strings
from __future__ import annotations

# Import the os module to interact with the operating system environment variables
import os
# Import the sys module to manipulate the Python runtime environment, specifically the module search path
import sys
# Import the Path class from pathlib for object-oriented filesystem path manipulations
from pathlib import Path

# Define a constant tuple containing the directory names of all core Vault OS internal sub-modules
_SUBPROJECTS = ("Access", "Devices", "Events", "Invites", "Personnel", "Vault")


def repository_root() -> Path:
    """Locates the base directory of the Vault OS workspace."""
    # Check for an environment variable 'VAULTOS_ROOT' that allows manual override of the project location
    override = os.environ.get("VAULTOS_ROOT", "").strip()
    # If the environment variable is set and not empty, use it as the source of truth
    if override:
        # Convert the string to a Path object, expand user symbols (like ~), and get the absolute path
        return Path(override).expanduser().resolve()
    # Otherwise, calculate the root relative to this file: move up two levels from facility/bootstrap.py
    return Path(__file__).resolve().parents[2]

def ensure_subproject_paths() -> None:
    """Injects the subproject directories into sys.path to enable direct imports of sibling modules."""
    # Retrieve the determined repository root directory
    root = repository_root()
    # Create a set of absolute paths currently in sys.path to avoid adding redundant or duplicate entries
    existing = {Path(entry).resolve() for entry in sys.path if entry}
    # Iterate through each subproject name defined in the _SUBPROJECTS constant
    for name in _SUBPROJECTS:
        # Construct the absolute path to the specific subproject folder
        path = (root / name).resolve()
        # If this subproject path is not already present in the Python environment's search path
        if path not in existing:
            # Append the path as a string to sys.path so its contents can be imported globally
            sys.path.append(str(path))
            # Add the new path to the tracking set to maintain uniqueness during the loop
            existing.add(path)
