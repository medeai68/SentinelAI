
"""Central project configuration for SentinelAI.

This file holds basic configuration only.
No passwords, API keys or secrets belong here -- real secrets go in a
local .env file (which is never committed to Git) or in the OS environment.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Load variables from a local ".env" file if one is present.
# If there is no .env file, this simply does nothing.
load_dotenv()

# --- Project identity ---------------------------------------------------

PROJECT_NAME = "SentinelAI"
PROJECT_VERSION = "1.0.0"

# Which environment the code runs in: "development", "testing" or
# "production". Read from an environment variable, default "development".
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

# --- Project folders ----------------------------------------------------

# Absolute path of the project root folder.
# This file lives at <project root>/config/settings.py, so going two
# parents up (config -> project root) gives us the root itself.
BASE_DIR = Path(__file__).resolve().parent.parent

# Common project folders, built on top of the project root.
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"
