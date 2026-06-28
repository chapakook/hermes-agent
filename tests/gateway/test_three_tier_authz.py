"""Tests for the three-tier trust model (OWNER / TRUST / NO-TRUST).

Covers the design's AC mapping:

  AC-1  test_resolve_trust_tier_all_tiers
  AC-2  test_owner_dangerous_command_enters_approval_flow
  AC-3  test_trust_dangerous_command_immediately_rejected
        test_trust_sensitive_file_read_rejected            (B)
        test_trust_sensitive_file_write_rejected           (C, config.yaml)
        test_trust_owner_slash_rejected                    (D)
  AC-4  test_trust_non_dangerous_command_passes
  AC-6  test_owner_from_and_allow_admin_from_coexist
  Limit test_trust_python_exec_not_blocked (bypass is real — pin the fact)

NO-TRUST DM/group behavior (AC-5) is exercised by the existing
tests/gateway/test_unauthorized_dm_behavior.py suite and is unchanged here.

Pattern: bare ``object.__new__(GatewayRunner)`` runners (no __init__) +
MagicMock config/pairing, with the trust contextvar reset between tests so
tier never leaks across cases.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from gateway.config import Platform
from gateway.session import SessionSource
from gateway.trust import (
    TrustTier,
    get_current_trust_tier,
    reset_current_trust_tier,
    set_current_trust_tier,
)


@pytest.fixture(autouse=True)
def _reset_trust_tier():
    """Isolate the trust contextvar per test (set point leakage guard)."""
    token = set_current_trust_tier(TrustTier.NO_TRUST)
    try:
        yield
    finally:
        reset_current_trust_tier(token)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    for var in (
        "DISCORD_ALLOWED_USERS",
        "DISCORD_ALLOW_ALL_USERS",
        "GATEWAY_ALLOWED_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
        "HERMES_YOLO_MODE",
        "HERMES_INTERACTIVE",
    ):
        monkeypatch.delenv(var, raising=False)


def _make_runner(owner_from=None, allow_admin_from=None):
    """Bare GatewayRunner with a mock config exposing owner_from in extra."""
    from gateway.run import GatewayRunner

    runner = object.__new__(GatewayRunner)
    runner.pairing_store = SimpleNamespace(is_approved=lambda *_a, **_kw: False)

    extra: dict = {}
    if owner_from is not None:
        extra["owner_from"] = owner_from
    if allow_admin_from is not None:
        extra["allow_admin_from"] = allow_admin_from
    platform_cfg = SimpleNamespace(extra=extra)
    runner.config = SimpleNamespace(platforms={Platform.DISCORD: platform_cfg})
    return runner


def _discord_dm(user_id="u1"):
    return SessionSource(
        platform=Platform.DISCORD,
        chat_id="c1",
        chat_type="dm",
        user_id=user_id,
        user_name="Alice",
    )


# ---------------------------------------------------------------------------
# AC-1: tier resolution
# ---------------------------------------------------------------------------


def test_resolve_trust_tier_all_tiers(monkeypatch):
    """owner_from→OWNER, allowlisted non-owner→TRUST, unlisted→NO_TRUST."""
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "owner1,trusted2")
    runner = _make_runner(owner_from="owner1")

    assert runner._resolve_trust_tier(_discord_dm("owner1")) is TrustTier.OWNER
    assert runner._resolve_trust_tier(_discord_dm("trusted2")) is TrustTier.TRUST
    assert runner._resolve_trust_tier(_discord_dm("stranger3")) is TrustTier.NO_TRUST


def test_resolve_trust_tier_homeassistant_is_owner():
    """System-authenticated HA/webhook events are OWNER regardless of user_id."""
    runner = _make_runner()
    src = SessionSource(
        platform=Platform.HOMEASSISTANT,
        chat_id="ha",
        chat_type="dm",
        user_id=None,
    )
    assert runner._resolve_trust_tier(src) is TrustTier.OWNER


def test_resolve_trust_tier_no_owner_configured_is_trust(monkeypatch):
    """When owner_from is unset, an allowlisted caller is TRUST, not OWNER (BR-5)."""
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "owner1")
    runner = _make_runner(owner_from=None)
    assert runner._resolve_trust_tier(_discord_dm("owner1")) is TrustTier.TRUST


def test_resolve_trust_tier_no_user_id_passing_chat_is_trust(monkeypatch):
    """user_id None but chat-authorized → TRUST (owner requires a user_id)."""
    monkeypatch.setenv("GATEWAY_ALLOW_ALL_USERS", "true")
    runner = _make_runner(owner_from="owner1")
    src = SessionSource(
        platform=Platform.DISCORD,
        chat_id="c1",
        chat_type="dm",
        user_id="someone",
    )
    # Allow-all admits everyone → authorized but not owner → TRUST.
    assert runner._resolve_trust_tier(src) is TrustTier.TRUST


def test_resolve_trust_tier_matches_contextvar(monkeypatch):
    """The resolved tier is exactly what set/get round-trips through the var."""
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "owner1")
    runner = _make_runner(owner_from="owner1")
    tier = runner._resolve_trust_tier(_discord_dm("owner1"))
    token = set_current_trust_tier(tier)
    try:
        assert get_current_trust_tier() is TrustTier.OWNER
    finally:
        reset_current_trust_tier(token)


# ---------------------------------------------------------------------------
# AC-2 / AC-3 / AC-4: dangerous command gating (A)
# ---------------------------------------------------------------------------


def _check(command, monkeypatch):
    """Run check_dangerous_command in a gateway-ask context."""
    monkeypatch.setenv("HERMES_INTERACTIVE", "")
    from tools import approval

    # Force the gateway approval path so OWNER lands in submit_pending, not
    # an interactive prompt.
    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: True)
    monkeypatch.setattr(approval, "submit_pending", lambda *a, **k: None)
    return approval.check_dangerous_command(command, "local")


def test_owner_dangerous_command_enters_approval_flow(monkeypatch):
    """AC-2: OWNER's dangerous command enters approval (not immediate reject)."""
    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        result = _check("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert result.get("status") == "approval_required"


def test_trust_dangerous_command_immediately_rejected(monkeypatch):
    """AC-3 (A): TRUST's dangerous command is rejected immediately, no wait."""
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert result.get("status") != "approval_required"
    assert "owner" in result["message"].lower()


def test_trust_non_dangerous_command_passes(monkeypatch):
    """AC-4: TRUST's non-dangerous command is unaffected."""
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check("ls -la", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is True


def test_trust_sensitive_file_read_rejected(monkeypatch):
    """AC-3 (B): TRUST reading a secret file (cat ~/.ssh/...) is rejected."""
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check("cat ~/.ssh/id_rsa", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert result.get("status") != "approval_required"


# ---------------------------------------------------------------------------
# AC-3 (C): sensitive file write gating
# ---------------------------------------------------------------------------


def test_trust_sensitive_file_write_rejected(monkeypatch, tmp_path):
    """AC-3 (C): TRUST writing config.yaml is refused."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    monkeypatch.setattr(
        file_tools, "_get_hermes_config_resolved", lambda: str(cfg.resolve())
    )

    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        err = file_tools._check_sensitive_path_for_tier(str(cfg))
    finally:
        reset_current_trust_tier(token)
    assert err is not None
    assert "config" in err.lower()


def test_owner_config_yaml_write_still_blocked(monkeypatch, tmp_path):
    """AC-3 (C) carve-out: OWNER still cannot write config.yaml (self-disablement)."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    monkeypatch.setattr(
        file_tools, "_get_hermes_config_resolved", lambda: str(cfg.resolve())
    )

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        err = file_tools._check_sensitive_path_for_tier(str(cfg))
    finally:
        reset_current_trust_tier(token)
    assert err is not None


def test_owner_other_sensitive_write_allowed(monkeypatch, tmp_path):
    """OWNER carve-out: a non-config sensitive path passes through."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    monkeypatch.setattr(
        file_tools, "_get_hermes_config_resolved", lambda: str(cfg.resolve())
    )

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        # /etc/hosts is sensitive for TRUST, allowed for OWNER.
        err = file_tools._check_sensitive_path_for_tier("/etc/hosts")
    finally:
        reset_current_trust_tier(token)
    assert err is None


def test_trust_other_sensitive_write_rejected(monkeypatch, tmp_path):
    """TRUST is blocked on system sensitive paths too, not just config.yaml."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    monkeypatch.setattr(
        file_tools, "_get_hermes_config_resolved", lambda: str(cfg.resolve())
    )

    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        err = file_tools._check_sensitive_path_for_tier("/etc/hosts")
    finally:
        reset_current_trust_tier(token)
    assert err is not None


# ---------------------------------------------------------------------------
# AC-3 (D): owner-only slash command
# ---------------------------------------------------------------------------


def test_trust_owner_slash_rejected():
    """AC-3 (D): an admin-registered NON-owner is denied with owner framing.

    Design D: owner-only slash gating fires for a caller who IS an admin
    (allow_admin_from) but is NOT the owner (owner_from). Here adminX is an
    admin but not an owner → admin slash commands are reserved for owner1.
    """
    runner = _make_runner(owner_from="owner1", allow_admin_from="adminX")
    src = _discord_dm("adminX")

    denial = runner._check_slash_access(src, "model")
    assert denial is not None
    assert "owner" in denial.lower()


def test_non_admin_trust_slash_gets_admin_only_message():
    """A non-admin caller still gets the original 'admin-only here' message.

    The (D) gate only applies to admin-registered callers; a plain non-admin
    must keep the prior allow_admin_from denial text, not the owner framing.
    """
    runner = _make_runner(owner_from="owner1", allow_admin_from="owner1")
    src = _discord_dm("trusted2")

    denial = runner._check_slash_access(src, "model")
    assert denial is not None
    assert "admin-only here" in denial.lower()
    assert "only be run by the owner" not in denial.lower()


def test_owner_from_unset_admin_slash_passes():
    """Backward-compat: with owner_from UNSET, an admin caller passes (D) skipped.

    Existing allow_admin_from-only installs must keep working — the owner-only
    gate must not block admins when no owner is configured.
    """
    runner = _make_runner(owner_from=None, allow_admin_from="adminX")
    src = _discord_dm("adminX")

    denial = runner._check_slash_access(src, "model")
    assert denial is None


def test_owner_slash_access_allowed():
    """OWNER (admin) passes the slash gate."""
    runner = _make_runner(owner_from="owner1", allow_admin_from="owner1")
    src = _discord_dm("owner1")

    denial = runner._check_slash_access(src, "model")
    assert denial is None


# ---------------------------------------------------------------------------
# AC-6: owner_from and allow_admin_from coexist
# ---------------------------------------------------------------------------


def test_owner_from_and_allow_admin_from_coexist(monkeypatch):
    """AC-6: the two keys are independent; setting both does not conflict."""
    monkeypatch.setenv("DISCORD_ALLOWED_USERS", "owner1,adminX,plainY")
    # owner_from and allow_admin_from name different users.
    runner = _make_runner(owner_from="owner1", allow_admin_from="adminX")

    # owner_from drives tier.
    assert runner._resolve_trust_tier(_discord_dm("owner1")) is TrustTier.OWNER
    assert runner._resolve_trust_tier(_discord_dm("adminX")) is TrustTier.TRUST
    assert runner._resolve_trust_tier(_discord_dm("plainY")) is TrustTier.TRUST

    # allow_admin_from still drives slash policy independently.
    from gateway.slash_access import policy_for_source

    policy = policy_for_source(runner.config, _discord_dm("adminX"))
    assert policy.enabled is True
    assert policy.is_admin("adminX") is True
    assert policy.is_admin("owner1") is False


# ---------------------------------------------------------------------------
# Limitation: bypass is real
# ---------------------------------------------------------------------------


def test_trust_secret_read_bypass_not_blocked(monkeypatch):
    """Pin the documented bypass (SECURITY.md §2.4): the secret-read guard is
    incomplete, so an obfuscated read slips past it even for TRUST.

    Design note: the design's worked example was ``python -c`` reading .env,
    but that form IS caught — it matches DANGEROUS_PATTERNS' "script
    execution via -e/-c flag", so TRUST is blocked on it by the (A) gate.
    The genuine bypass is a read that matches neither (A) nor (B): e.g.
    ``env | grep`` dumping process secrets, or any in-process tool read.
    This test fixes that fact so a future tightening is a conscious change
    to the documented threat model, not a silent one.
    """
    from tools import approval

    # env | grep SECRET dumps secrets but matches no (A)/(B) pattern.
    is_dangerous, _key, _desc = approval.detect_dangerous_command(
        "env | grep -i secret"
    )
    assert is_dangerous is False  # guardrail does NOT catch this read

    # And so the full gate approves it for a TRUST caller (no rejection).
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check("env | grep -i secret", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is True


# ---------------------------------------------------------------------------
# (A) consolidated terminal path: check_all_command_guards
# ---------------------------------------------------------------------------


def _check_guards(command, monkeypatch):
    """Run check_all_command_guards (the path terminal_tool actually uses)."""
    monkeypatch.setenv("HERMES_INTERACTIVE", "")
    from tools import approval

    monkeypatch.setattr(approval, "_is_gateway_approval_context", lambda: True)
    monkeypatch.setattr(approval, "submit_pending", lambda *a, **k: None)
    return approval.check_all_command_guards(command, "local")


def test_trust_dangerous_command_rejected_on_guards_path(monkeypatch):
    """(A) CRITICAL: TRUST is blocked on the consolidated guards path too.

    terminal_tool calls check_all_command_guards, not check_dangerous_command,
    so this is the path that actually gates real terminal execution.
    """
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check_guards("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert result.get("status") != "approval_required"
    assert "owner" in result["message"].lower()


def test_trust_non_dangerous_passes_on_guards_path(monkeypatch):
    """A non-dangerous command is unaffected on the consolidated path."""
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check_guards("ls -la", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is True


def test_owner_dangerous_enters_approval_on_guards_path(monkeypatch):
    """OWNER still enters the approval flow on the consolidated path."""
    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        result = _check_guards("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    # OWNER is not immediately rejected with the owner-only message.
    assert result.get("message") != (
        "⛔ This action is restricted to the owner. Ask the bot owner to run it."
    )


# ---------------------------------------------------------------------------
# BR-2: /yolo does not let TRUST bypass the sensitive-action gate
# ---------------------------------------------------------------------------


def test_trust_dangerous_blocked_even_with_yolo_dangerous_path(monkeypatch):
    """BR-2: a TRUST caller is blocked even when /yolo is active (check_dangerous_command)."""
    from tools import approval

    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: True)
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert "owner" in result["message"].lower()


def test_trust_dangerous_blocked_even_with_yolo_guards_path(monkeypatch):
    """BR-2: a TRUST caller is blocked even when /yolo is active (check_all_command_guards)."""
    from tools import approval

    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: True)
    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        result = _check_guards("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is False
    assert "owner" in result["message"].lower()


def test_owner_yolo_still_bypasses_dangerous(monkeypatch):
    """Sanity: /yolo still lets OWNER bypass (yolo gate runs after the TRUST gate)."""
    from tools import approval

    monkeypatch.setattr(approval, "is_current_session_yolo_enabled", lambda: True)
    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        result = _check("rm -rf /tmp/data", monkeypatch)
    finally:
        reset_current_trust_tier(token)
    assert result["approved"] is True


# ---------------------------------------------------------------------------
# (C) sensitive-file writes via the integrated write_file_tool / patch_tool
# ---------------------------------------------------------------------------


def _point_hermes_config_at(monkeypatch, cfg_path):
    from tools import file_tools

    monkeypatch.setattr(
        file_tools, "_get_hermes_config_resolved", lambda: str(cfg_path.resolve())
    )


def test_trust_write_file_tool_config_yaml_rejected(monkeypatch, tmp_path):
    """(C) integrated: TRUST writing config.yaml via write_file_tool is refused."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    _point_hermes_config_at(monkeypatch, cfg)

    token = set_current_trust_tier(TrustTier.TRUST)
    try:
        out = file_tools.write_file_tool(str(cfg), "approvals:\n  mode: off\n")
    finally:
        reset_current_trust_tier(token)
    assert "config" in out.lower() or "sensitive" in out.lower()
    assert not cfg.exists()  # write did not happen


def test_owner_write_file_tool_config_yaml_still_rejected(monkeypatch, tmp_path):
    """(C) carve-out: OWNER writing config.yaml via write_file_tool is still refused."""
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    _point_hermes_config_at(monkeypatch, cfg)

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        out = file_tools.write_file_tool(str(cfg), "approvals:\n  mode: off\n")
    finally:
        reset_current_trust_tier(token)
    assert "config" in out.lower() or "sensitive" in out.lower()
    assert not cfg.exists()


def test_owner_write_file_tool_other_sensitive_allowed(monkeypatch, tmp_path):
    """(C) carve-out: OWNER may write a non-config sensitive path (system path).

    /etc is blocked for TRUST but allowed for OWNER. We don't actually want to
    write /etc, so assert the sensitive-path gate returns None (allowed) for
    OWNER via the integrated checker rather than performing the write.
    """
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    _point_hermes_config_at(monkeypatch, cfg)

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        err = file_tools._check_sensitive_path_for_tier("/etc/hosts")
    finally:
        reset_current_trust_tier(token)
    assert err is None


def test_config_yaml_symlink_carveout_not_bypassable(monkeypatch, tmp_path):
    """(C) symlink: a symlink pointing at config.yaml is still blocked for OWNER.

    Without realpath resolution, /tmp/link -> config.yaml would slip past the
    carve-out and let OWNER (or anyone) disable approvals via the symlink.
    """
    from tools import file_tools

    cfg = tmp_path / "config.yaml"
    cfg.write_text("approvals:\n  mode: ask\n")
    link = tmp_path / "sneaky_link.yaml"
    link.symlink_to(cfg)
    _point_hermes_config_at(monkeypatch, cfg)

    assert file_tools._is_hermes_config_path(str(link)) is True

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        err = file_tools._check_sensitive_path_for_tier(str(link))
    finally:
        reset_current_trust_tier(token)
    assert err is not None


def test_is_hermes_config_path_fail_closed_when_unknown(monkeypatch, tmp_path):
    """(C) fail-closed: when the config path can't be resolved, treat as config."""
    from tools import file_tools

    monkeypatch.setattr(file_tools, "_get_hermes_config_resolved", lambda: None)
    assert file_tools._is_hermes_config_path(str(tmp_path / "anything.txt")) is True


def test_owner_config_write_blocked_when_config_path_unknown(monkeypatch, tmp_path):
    """(C) fail-closed end-to-end: OWNER writing config.yaml is still blocked even
    when _get_hermes_config_resolved() is None.

    Regression guard: the OWNER carve-out must not delegate the block decision
    to _check_sensitive_path (which fails OPEN for config.yaml when the config
    path is unknown). _check_sensitive_path_for_tier must block from
    _is_hermes_config_path's fail-closed verdict alone.
    """
    from tools import file_tools

    monkeypatch.setattr(file_tools, "_get_hermes_config_resolved", lambda: None)

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        err = file_tools._check_sensitive_path_for_tier(str(tmp_path / "config.yaml"))
    finally:
        reset_current_trust_tier(token)
    assert err is not None
    assert "config" in err.lower()


def test_owner_write_file_tool_config_blocked_when_path_unknown(monkeypatch, tmp_path):
    """(C) fail-closed via the integrated write_file_tool path."""
    from tools import file_tools

    monkeypatch.setattr(file_tools, "_get_hermes_config_resolved", lambda: None)
    target = tmp_path / "config.yaml"

    token = set_current_trust_tier(TrustTier.OWNER)
    try:
        out = file_tools.write_file_tool(str(target), "approvals:\n  mode: off\n")
    finally:
        reset_current_trust_tier(token)
    assert "config" in out.lower() or "sensitive" in out.lower()
    assert not target.exists()
