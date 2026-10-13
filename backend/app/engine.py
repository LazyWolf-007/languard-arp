from time import perf_counter_ns
from .models import Alert, Decision, Event, Evaluation, Mapping, Mode, Observation, Severity, now


def evaluate(alerts: list[Alert], events: list[Event]) -> Evaluation:
    labelled = [e for e in events if e.label in {"positive", "negative"}]
    detected = {a.scenario for a in alerts if a.scenario and a.label == "positive"}
    positive_scenarios = {e.scenario for e in labelled if e.label == "positive" and e.scenario}
    tp = len(detected & positive_scenarios)
    fn = len(positive_scenarios - detected)
    false_positive_scenarios = {a.scenario for a in alerts if a.label == "negative" and a.scenario}
    negatives = {e.scenario for e in labelled if e.label == "negative" and e.scenario}
    fp = len(false_positive_scenarios)
    tn = len(negatives - false_positive_scenarios)
    latencies = [a.latency_ms for a in alerts if a.label == "positive" and a.latency_ms is not None]
    return Evaluation(tp=tp, fp=fp, fn=fn, tn=tn,
                      precision=tp / (tp + fp) if tp + fp else None,
                      recall=tp / (tp + fn) if tp + fn else None,
                      latency_ms_mean=sum(latencies) / len(latencies) if latencies else None,
                      labelled_positives=len(positive_scenarios), labelled_negatives=len(negatives),
                      unknown_events=sum(1 for e in events if e.label is None or e.scenario is None),
                      note="Metrics use labelled simulation scenarios only; real-network ground truth is unavailable.")


def process(obs: Observation, mappings: dict[str, Mapping], mode: Mode,
            alerts: list[Alert], decisions: list[Decision], events: list[Event], next_id) -> tuple[Alert | None, Event]:
    started = perf_counter_ns()
    current = mappings.get(obs.ip)
    trusted = current.trusted_mac if current else None
    conflict = bool(current and current.mac != obs.mac and not obs.legitimate
                    and (current.trusted_mac is None or current.trusted_mac != obs.mac))
    unexpected = bool(trusted and trusted != obs.mac and not obs.legitimate)
    suspicious_unsolicited = obs.unsolicited and not obs.legitimate
    alert = None
    if unexpected or conflict or suspicious_unsolicited:
        severity = Severity.critical if obs.ip == "192.168.1.1" else Severity.high if unexpected else Severity.medium
        reason_parts = []
        if unexpected: reason_parts.append("Observed MAC differs from the explicitly trusted baseline")
        if conflict: reason_parts.append("Conflicting IP-to-MAC claim detected")
        if suspicious_unsolicited: reason_parts.append("Unsolicited ARP announcement has no trusted-change evidence")
        alert = Alert(id=next_id("alert"), severity=severity, type="mapping_conflict" if conflict else "unsolicited_arp",
                      affected_ip=obs.ip, previous_mac=current.mac if current else trusted,
                      observed_mac=obs.mac, reason="; ".join(reason_parts), scenario=obs.scenario,
                      label=obs.label, latency_ms=(perf_counter_ns() - started) / 1_000_000)
        alerts.append(alert)
        untrusted_update = current is None or bool(current and current.trusted_mac is None)
        action = "rejected" if mode == Mode.enforcement and (unexpected or untrusted_update) else "observed"
        if action == "rejected":
            decisions.append(Decision(id=next_id("decision"), ip=obs.ip, mac=obs.mac, action=action,
                                      reason="Simulated enforcement preserved the trusted mapping"))
        else:
            decisions.append(Decision(id=next_id("decision"), ip=obs.ip, mac=obs.mac, action=action,
                                      reason="Monitoring mode records suspicious claims without network enforcement"))
        if current and action == "rejected":
            if current.trusted_mac:
                current.mac = current.trusted_mac
                current.status = "trusted"
                current.updated_at = now()
        elif current and conflict:
            current.mac = obs.mac
            current.status = "conflict"
            current.updated_at = now()
        elif current:
            current.mac = obs.mac
            if obs.legitimate:
                current.trusted_mac = obs.mac
                current.status = "trusted"
            elif current.trusted_mac == obs.mac:
                current.status = "trusted"
            current.updated_at = now()
        elif action != "rejected":
            mappings[obs.ip] = Mapping(ip=obs.ip, mac=obs.mac, trusted_mac=None, status="untrusted")
        rejected = action == "rejected"
    else:
        rejected = False
        if current and mode == Mode.enforcement and current.trusted_mac is None and not obs.legitimate:
            rejected = True
            decisions.append(Decision(id=next_id("decision"), ip=obs.ip, mac=obs.mac, action="rejected",
                                      reason="Simulated enforcement rejected a mapping without a trusted baseline"))
        elif current:
            current.mac = obs.mac
            if obs.legitimate:
                current.trusted_mac = obs.mac
                current.status = "trusted"
            elif current.trusted_mac == obs.mac:
                current.status = "trusted"
            current.updated_at = now()
        elif mode == Mode.enforcement and not obs.legitimate:
            rejected = True
            decisions.append(Decision(id=next_id("decision"), ip=obs.ip, mac=obs.mac, action="rejected",
                                      reason="Simulated enforcement rejected a mapping without a trusted baseline"))
        else:
            mappings[obs.ip] = Mapping(ip=obs.ip, mac=obs.mac, trusted_mac=obs.mac if obs.legitimate else None,
                                       status="trusted" if obs.legitimate else "observed")
    status = "alert" if alert else "rejected" if rejected else "accepted"
    message = alert.reason if alert else "Simulated enforcement rejected a mapping without a trusted baseline" if rejected else f"ARP mapping observed for {obs.ip}"
    event = Event(id=next_id("event"), type="arp_observation", severity=alert.severity if alert else Severity.info,
                  status=status, message=message,
                  ip=obs.ip, mac=obs.mac, alert_id=alert.id if alert else None,
                  scenario=obs.scenario, label=obs.label)
    events.append(event)
    return alert, event
