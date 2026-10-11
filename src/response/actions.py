"""Response actions, modes and statuses (Part 7).

Authorization boundary — four distinct concepts, never conflated:

    1. Detection            (the model's prediction)          — src/detection/
    2. Recommended response (what the policy suggests)        — policies.py
    3. Simulated response   (DRY_RUN_BLOCK, nothing changes)  — this module
    4. Actual authorized response (BLOCK_REQUESTED)           — only via an
       explicitly supplied, isolated adapter, and only in AUTHORIZED mode.

This project ships NO real firewall/network adapter: the AUTHORIZED path
requires the caller to supply an isolated adapter (e.g. one scoped to a
local authorized test environment). Nothing here modifies the operating
system firewall or network configuration.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

# ---------------------------------------------------------------
#  Response modes
# ---------------------------------------------------------------

MODE_DRY_RUN = "DRY_RUN"          # default: simulate + log only
MODE_AUTHORIZED = "AUTHORIZED"    # opt-in: requires an explicit adapter
RESPONSE_MODES = (MODE_DRY_RUN, MODE_AUTHORIZED)
DEFAULT_RESPONSE_MODE = MODE_DRY_RUN

# ---------------------------------------------------------------
#  Response actions (states)
# ---------------------------------------------------------------

ACTION_NO_ACTION = "NO_ACTION"
ACTION_ALERT_ONLY = "ALERT_ONLY"
ACTION_DRY_RUN_BLOCK = "DRY_RUN_BLOCK"
ACTION_BLOCK_REQUESTED = "BLOCK_REQUESTED"
RESPONSE_ACTIONS = (
    ACTION_NO_ACTION,
    ACTION_ALERT_ONLY,
    ACTION_DRY_RUN_BLOCK,
    ACTION_BLOCK_REQUESTED,
)

# ---------------------------------------------------------------
#  Response statuses
# ---------------------------------------------------------------

STATUS_NONE = "NONE"              # no action was warranted
STATUS_LOGGED = "LOGGED"          # alert recorded, nothing else
STATUS_SIMULATED = "SIMULATED"    # dry-run: what WOULD happen, nothing changed
STATUS_AUTHORIZED = "AUTHORIZED"  # isolated authorized adapter executed
STATUS_FAILED = "FAILED"          # adapter attempted and failed
STATUS_SKIPPED = "SKIPPED"        # detection invalid — response not applicable

STATUS_FOR_ACTION = {
    ACTION_NO_ACTION: STATUS_NONE,
    ACTION_ALERT_ONLY: STATUS_LOGGED,
    ACTION_DRY_RUN_BLOCK: STATUS_SIMULATED,
    ACTION_BLOCK_REQUESTED: STATUS_AUTHORIZED,
}


def status_for(action: str) -> str:
    """Map a response action to its default status."""
    return STATUS_FOR_ACTION[action]


# ---------------------------------------------------------------
#  Execution adapter (AUTHORIZED mode only)
# ---------------------------------------------------------------

@runtime_checkable
class ResponseExecutor(Protocol):
    """Isolated adapter interface for AUTHORIZED mode.

    No implementation is shipped with this project. Supplying one is an
    explicit opt-in decision by the caller, and any implementation must
    be restricted to a local, authorized test environment. In DRY_RUN
    mode the engine NEVER calls an executor, even if one is provided.
    """

    def block(self, *, flow_id: str | None, reason: str) -> None:
        """Request a block for the given flow. Must not raise silently."""
        ...
