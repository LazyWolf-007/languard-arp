from app.models import Alert, Decision, Event, Mode, Severity
from app.state import State


def test_reset_restores_consistent_trusted_baseline():
    state = State()
    original = state.snapshot()
    state.mode = Mode.enforcement
    state.monitoring = False
    state.mappings["192.168.1.1"].mac = "02:de:ad:be:ef:99"
    state.alerts.append(Alert(id="a", severity=Severity.high, type="mapping_conflict",
                              affected_ip="192.168.1.1", observed_mac="02:de:ad:be:ef:99", reason="test"))
    state.events.append(Event(id="e", type="arp_observation", severity=Severity.high,
                              status="alert", message="test"))
    state.decisions.append(Decision(id="d", ip="192.168.1.1", mac="02:de:ad:be:ef:99",
                                    action="rejected", reason="test"))

    state.reset()
    reset = state.snapshot()
    gateway = next(m for m in reset.mappings if m.ip == "192.168.1.1")
    assert gateway.mac == gateway.trusted_mac == "02:00:00:00:00:01"
    assert gateway.status == "trusted"
    assert reset.mode == Mode.monitoring and reset.monitoring
    assert not reset.alerts and not reset.events and not reset.decisions
    assert reset.devices == original.devices
