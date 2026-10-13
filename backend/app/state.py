from .models import Device, Mapping, Mode, Snapshot, now
from .engine import evaluate


class State:
    def __init__(self): self.reset()
    def reset(self):
        self.devices = [
            Device(id="gateway", name="Edge Gateway", ip="192.168.1.1", mac="02:00:00:00:00:01", role="gateway", trust="trusted"),
            Device(id="client-1", name="Workstation", ip="192.168.1.10", mac="02:00:00:00:00:10", role="client", trust="trusted"),
            Device(id="client-2", name="Lab Laptop", ip="192.168.1.11", mac="02:00:00:00:00:11", role="client", trust="trusted"),
            Device(id="rogue", name="Unknown Device", ip="192.168.1.99", mac="02:de:ad:be:ef:99", role="simulated rogue", trust="untrusted"),
        ]
        self.mappings = {d.ip: Mapping(ip=d.ip, mac=d.mac, trusted_mac=d.mac, status="trusted") for d in self.devices if d.id != "rogue"}
        self.alerts, self.events, self.decisions = [], [], []
        self.mode, self.monitoring = Mode.monitoring, True
        self.counter = 0
    def id(self, prefix):
        self.counter += 1
        return f"{prefix}-{self.counter:04d}"
    def snapshot(self):
        return Snapshot(devices=self.devices, mappings=list(self.mappings.values()), alerts=list(reversed(self.alerts)),
                        events=list(reversed(self.events)), decisions=list(reversed(self.decisions)), mode=self.mode,
                        monitoring=self.monitoring, evaluation=evaluate(self.alerts, self.events))

state = State()
