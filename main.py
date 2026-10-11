"""
SentinelAI — AI-Powered Network Intrusion Detection and Threat Analysis System.

Entry point for the project.

Current phase (Part 2): project foundation.
This script only confirms that the development environment is set up.
Detection logic is added in later phases.
"""

import sys


def main() -> None:
    """Display the project banner and confirm the environment is ready."""
    in_virtual_env = sys.prefix != sys.base_prefix

    print("========================================")
    print("SentinelAI")
    print("AI-Powered Network Intrusion Detection")
    print("and Threat Analysis System")
    print("==========================")
    print()
    print("Version 1.0.0 - research prototype (development parts complete)")
    if in_virtual_env:
        print("Environment: Ready")
    else:
        print("Environment: Ready (system Python - see DEVELOPMENT.md)")


if __name__ == "__main__":
    main()
