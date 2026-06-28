"""Per-message trust tier for the gateway 3-tier authorization model.

A message sender is resolved once at intake (``GatewayAuthorizationMixin.
_resolve_trust_tier``) into one of three tiers and bound to a context-local
variable so per-tool-call gates (dangerous-command approval, sensitive-file
writes, owner-only slash commands) can read it without threading the value
through every call.

This is an *in-process heuristic*, NOT a security boundary. It exists to keep
a well-intentioned TRUST caller from accidentally triggering owner-only
sensitive actions. A determined or prompt-injected agent can still bypass it
(``python -c``, ``xxd``, ``env | grep``, etc.). Real isolation comes from
running separate agent instances with separate allowlists / OS-level wrapping
(see SECURITY.md §2.4).

The contextvar pattern mirrors ``tools/approval.py``'s ``_approval_session_key``
(set/get/reset returning a token). This module imports nothing from other
gateway modules, so it stays free of import cycles.
"""

from __future__ import annotations

import contextvars
import enum


class TrustTier(enum.Enum):
    """Trust level of a message sender, resolved once at intake.

    - ``OWNER``: a sender listed in the config ``owner_from`` /
      ``group_owner_from`` key (by user_id), or a system-internal /
      Home Assistant / webhook event. May run every action, including
      sensitive ones (subject to the normal approval flow).
    - ``TRUST``: a sender that passed the existing access gate
      (``_is_user_authorized``) but is not an owner. Normal conversation and
      non-sensitive tools are unaffected; sensitive actions are rejected.
    - ``NO_TRUST``: a sender that did not pass the access gate. Current
      behavior is unchanged (DM → pairing code, group → silent ignore).
    """

    OWNER = "owner"
    TRUST = "trust"
    NO_TRUST = "no_trust"


# Per-thread/per-task trust tier of the message currently being handled.
# Gateway runs agent turns concurrently in executor threads, so a process-
# global would be racy; a context-local value is snapshotted by
# ``copy_context()`` and rebound on the executor thread (see gateway/run.py).
# Defaults to NO_TRUST so any unbound code path fails closed.
_current_trust_tier: contextvars.ContextVar[TrustTier] = contextvars.ContextVar(
    "current_trust_tier",
    default=TrustTier.NO_TRUST,
)


def set_current_trust_tier(tier: TrustTier) -> contextvars.Token[TrustTier]:
    """Bind the active trust tier to the current context."""
    return _current_trust_tier.set(tier)


def reset_current_trust_tier(token: contextvars.Token[TrustTier]) -> None:
    """Restore the prior trust tier context."""
    _current_trust_tier.reset(token)


def get_current_trust_tier() -> TrustTier:
    """Return the active trust tier, defaulting to ``NO_TRUST`` (fail closed)."""
    return _current_trust_tier.get()
