"""The panel configures the agent, except where the operator pinned a value.

This is what makes an install a URL and a token and nothing else — and the
pinning is what stops a value set on the machine from being silently
overwritten on the first report.
"""

import pytest
from cherubyte_protocol import AgentConfig

from cherubyte_agent import config as agent_config
from cherubyte_agent.config import apply_config, settings


@pytest.fixture(autouse=True)
def _restore():
    before = {f: getattr(settings, f) for f in AgentConfig.model_fields if hasattr(settings, f)}
    yield
    for field, value in before.items():
        setattr(settings, field, value)


def test_the_panel_drives_an_unpinned_field():
    apply_config(AgentConfig(scan_interval_seconds=300), pinned=frozenset())
    assert settings.scan_interval_seconds == 300


def test_a_pinned_field_is_left_alone():
    settings.scan_interval_seconds = 60
    changed = apply_config(
        AgentConfig(scan_interval_seconds=300), pinned=frozenset({"scan_interval_seconds"})
    )
    assert settings.scan_interval_seconds == 60
    assert "scan_interval_seconds" not in changed


def test_only_what_actually_changed_is_reported():
    settings.scan_interval_seconds = 300
    settings.identify_batch = 16
    changed = apply_config(
        AgentConfig(scan_interval_seconds=300, identify_batch=4), pinned=frozenset()
    )
    assert changed == ["identify_batch"]


def test_subnets_arrive_in_the_shape_the_scanner_reads():
    """The wire carries plain CIDRs; the scanner wants {cidr,label} entries."""
    apply_config(AgentConfig(subnets=["192.168.1.0/24"]), pinned=frozenset())
    assert settings.subnets == [{"cidr": "192.168.1.0/24", "label": ""}]


def test_every_config_field_maps_onto_a_real_setting():
    """A field the panel sends that the agent has no home for would be dropped
    in silence — the exact failure the shared protocol exists to prevent."""
    unknown = {
        f for f in AgentConfig.model_fields if not hasattr(settings, f)
    }
    assert not unknown, f"the panel can send {unknown}, which the agent cannot store"


def test_pinned_is_a_snapshot_of_startup_not_a_live_view():
    """It has to be frozen at import.

    `model_fields_set` grows every time anything assigns to a setting — so a
    live view would pin each field the moment the panel first configured it,
    and the panel would be able to change every value exactly once.
    """
    before = set(agent_config.PINNED)
    apply_config(AgentConfig(scan_interval_seconds=123), pinned=frozenset())
    assert set(agent_config.PINNED) == before
    assert isinstance(agent_config.PINNED, frozenset)
