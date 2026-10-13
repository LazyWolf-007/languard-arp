from .models import Observation


def normal_observation(scenario: str, client_ip: str = "192.168.1.10",
                       client_mac: str = "02:00:00:00:00:10") -> Observation:
    return Observation(ip=client_ip, mac=client_mac, scenario=scenario, label="negative")


def gateway_spoof_observation(scenario: str) -> Observation:
    return Observation(ip="192.168.1.1", mac="02:de:ad:be:ef:99", unsolicited=True,
                       scenario=scenario, label="positive")


def demo_observations(id_factory) -> list[Observation]:
    return [normal_observation(id_factory("normal")),
            normal_observation(id_factory("normal"), "192.168.1.11", "02:00:00:00:00:11"),
            gateway_spoof_observation(id_factory("spoof"))]
