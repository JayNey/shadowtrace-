"""Sangfor capability overlay gates (alignment plan Layer 2)."""

from __future__ import annotations

import importlib.util

from app.adapters.sangfor.capability_overlay import (
    KERNEL_RESPONSE_NAMES,
    MOCK_ADAPTER_KIND,
    SANGFOR_ADAPTER_KIND,
    SangforDevice,
    SangforOverlayConfig,
    apply_capability_overlay,
)
from app.models.enums import ExecutionOwner, ToolCategory
from app.models.tool_meta import TERMINAL_DISPOSITION_TOOL
from app.tools.specs import baseline_tool_index

_AF = SangforDevice(device_type="AF", device_id="af-1")
_EDR = SangforDevice(device_type="EDR", device_id="edr-1")


def _overlay(config: SangforOverlayConfig):
    return apply_capability_overlay(baseline_tool_index(), config)


def test_execution_owner_still_has_two_members() -> None:
    assert {member.value for member in ExecutionOwner} == {"xdr_managed", "direct_tool"}
    assert len(ExecutionOwner) == 2
    assert not hasattr(ExecutionOwner, "MANUAL")
    assert "manual" not in {member.value for member in ExecutionOwner}


def test_kernel_catalog_still_contains_required_response_names() -> None:
    idx = baseline_tool_index()
    missing = KERNEL_RESPONSE_NAMES - set(idx)
    assert not missing
    isolate = idx["isolate_host"]
    assert isolate.executable is True
    assert set(isolate.supported_execution_owners) == {
        ExecutionOwner.XDR_MANAGED,
        ExecutionOwner.DIRECT_TOOL,
    }


def test_mock_kind_is_identity_and_keeps_both_owners() -> None:
    baseline = baseline_tool_index()
    overlaid = _overlay(SangforOverlayConfig(adapter_kind=MOCK_ADAPTER_KIND, devices=(_AF,)))
    isolate = overlaid["isolate_host"]
    assert isolate.executable is True
    assert set(isolate.supported_execution_owners) == {
        ExecutionOwner.XDR_MANAGED,
        ExecutionOwner.DIRECT_TOOL,
    }
    assert overlaid["disable_account"].supported_execution_owners == (
        baseline["disable_account"].supported_execution_owners
    )
    assert overlaid.keys() == baseline.keys()
    for name, meta in baseline.items():
        copied = overlaid[name]
        assert copied.tool_name == meta.tool_name
        assert copied.executable is meta.executable
        assert list(copied.supported_execution_owners) == list(meta.supported_execution_owners)
        assert copied is not meta


def test_sangfor_unsupported_write_clears_both_owners_but_keeps_tool() -> None:
    overlaid = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="network",
            devices=(_AF,),
        )
    )
    for name in ("isolate_host", "disable_account", "block_process", "quarantine_file"):
        meta = overlaid[name]
        assert name in overlaid
        assert meta.executable is True
        assert ExecutionOwner.XDR_MANAGED not in meta.supported_execution_owners
        assert ExecutionOwner.DIRECT_TOOL not in meta.supported_execution_owners
        assert list(meta.supported_execution_owners) == []
    baseline = baseline_tool_index()["isolate_host"]
    assert ExecutionOwner.XDR_MANAGED in baseline.supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL in baseline.supported_execution_owners


def test_block_domain_keeps_xdr_with_af_network_channel() -> None:
    overlaid = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="network",
            devices=(_AF,),
        )
    )
    domain = overlaid["block_domain"]
    assert ExecutionOwner.XDR_MANAGED in domain.supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL not in domain.supported_execution_owners
    assert domain.executable is True


def test_block_domain_drops_xdr_when_channel_is_endpoint() -> None:
    overlaid = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="endpoint",
            devices=(_AF, _EDR),
        )
    )
    domain = overlaid["block_domain"]
    assert ExecutionOwner.XDR_MANAGED not in domain.supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL not in domain.supported_execution_owners
    ip_meta = overlaid["block_ip"]
    assert ExecutionOwner.XDR_MANAGED in ip_meta.supported_execution_owners


def test_block_ip_endpoint_needs_edr_device() -> None:
    with_edr = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="endpoint",
            devices=(_EDR,),
        )
    )
    assert ExecutionOwner.XDR_MANAGED in with_edr["block_ip"].supported_execution_owners
    without = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="endpoint",
            devices=(),
        )
    )
    assert list(without["block_ip"].supported_execution_owners) == []
    assert list(without["block_domain"].supported_execution_owners) == []


def test_scan_and_ticket_require_config() -> None:
    incomplete = _overlay(
        SangforOverlayConfig(adapter_kind=SANGFOR_ADAPTER_KIND, devices=())
    )
    assert list(incomplete["scan_host_for_virus"].supported_execution_owners) == []
    assert list(incomplete["create_ticket"].supported_execution_owners) == []

    ready = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            devices=(_AF,),
            ticket_template_id="incidentBulletin",
            ticket_assignee_ids=("user-1",),
        )
    )
    assert ExecutionOwner.XDR_MANAGED in ready["scan_host_for_virus"].supported_execution_owners
    ticket = ready["create_ticket"]
    assert ExecutionOwner.XDR_MANAGED in ticket.supported_execution_owners
    assert ExecutionOwner.DIRECT_TOOL not in ticket.supported_execution_owners
    assert ticket.executable is True


def test_notify_and_disposition_and_non_response_are_untouched_owners() -> None:
    baseline = baseline_tool_index()
    overlaid = _overlay(
        SangforOverlayConfig(
            adapter_kind=SANGFOR_ADAPTER_KIND,
            block_channel="network",
            devices=(_AF,),
        )
    )
    assert list(overlaid["notify_security_team"].supported_execution_owners) == []
    disp = overlaid[TERMINAL_DISPOSITION_TOOL]
    assert disp.supported_execution_owners == [ExecutionOwner.XDR_MANAGED]
    assert disp.executable is False
    query = overlaid["query_dns"]
    assert query.tool_category is ToolCategory.QUERY
    assert list(query.supported_execution_owners) == []
    rollback = overlaid["cancel_host_isolation"]
    assert rollback.tool_category is ToolCategory.ROLLBACK
    assert list(rollback.supported_execution_owners) == list(
        baseline["cancel_host_isolation"].supported_execution_owners
    )


def test_forbidden_effector_modules_do_not_exist() -> None:
    assert importlib.util.find_spec("app.models.effector") is None
    assert importlib.util.find_spec("app.services.effector_resolver") is None
