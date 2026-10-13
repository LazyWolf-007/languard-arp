from app.engine import evaluate, process
from app.models import Alert, Event, Mapping, Mode, Observation

def run(obs, mode=Mode.monitoring):
    maps={"192.168.1.1": Mapping(ip="192.168.1.1",mac="aa:aa:aa:aa:aa:aa",trusted_mac="aa:aa:aa:aa:aa:aa",status="trusted")}
    alerts=[]; decisions=[]; events=[]; n=[0]
    def ident(prefix): n[0]+=1; return f"{prefix}-{n[0]}"
    alert,event=process(obs,maps,mode,alerts,decisions,events,ident)
    return alert,maps,decisions,events

def test_normal_arp_is_accepted():
    alert,_,_,events=run(Observation(ip="192.168.1.1",mac="aa:aa:aa:aa:aa:aa"))
    assert alert is None and events[0].status=="accepted"

def test_spoofed_gateway_mapping_raises_alert():
    alert,_,_,_=run(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb",label="positive"))
    assert alert and alert.severity.value=="critical" and alert.previous_mac=="aa:aa:aa:aa:aa:aa"

def test_conflicting_claim_detected():
    alert,maps,decisions,events=run(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb"))
    assert alert and "Conflicting" in alert.reason
    assert maps["192.168.1.1"].status=="conflict" and maps["192.168.1.1"].trusted_mac=="aa:aa:aa:aa:aa:aa"
    assert decisions[0].action=="observed" and events[0].status=="alert"

def test_legitimate_change_updates_mapping_without_alert():
    alert,maps,_,_=run(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb",legitimate=True))
    assert alert is None and maps["192.168.1.1"].mac=="bb:bb:bb:bb:bb:bb" and maps["192.168.1.1"].trusted_mac=="bb:bb:bb:bb:bb:bb"

def test_enforcement_preserves_mapping_and_records_decision():
    alert,maps,decisions,_=run(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb"),Mode.enforcement)
    assert alert and maps["192.168.1.1"].mac=="aa:aa:aa:aa:aa:aa" and decisions[0].action=="rejected"

def test_enforcement_restores_baseline_after_monitoring_observed_conflict():
    maps={"192.168.1.1": Mapping(ip="192.168.1.1",mac="aa:aa:aa:aa:aa:aa",trusted_mac="aa:aa:aa:aa:aa:aa",status="trusted")}
    alerts=[]; decisions=[]; events=[]; n=[0]
    def ident(prefix): n[0]+=1; return f"{prefix}-{n[0]}"
    suspicious=Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb")
    process(suspicious,maps,Mode.monitoring,alerts,decisions,events,ident)
    assert maps["192.168.1.1"].mac=="bb:bb:bb:bb:bb:bb"
    process(suspicious,maps,Mode.enforcement,alerts,decisions,events,ident)
    assert maps["192.168.1.1"].mac=="aa:aa:aa:aa:aa:aa"
    assert maps["192.168.1.1"].status=="trusted" and decisions[-1].action=="rejected"

def test_trusted_claim_clears_prior_monitoring_conflict_without_alert():
    maps={"192.168.1.1": Mapping(ip="192.168.1.1",mac="aa:aa:aa:aa:aa:aa",trusted_mac="aa:aa:aa:aa:aa:aa",status="trusted")}
    alerts=[]; decisions=[]; events=[]; n=[0]
    def ident(prefix): n[0]+=1; return f"{prefix}-{n[0]}"
    process(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb"),maps,Mode.monitoring,alerts,decisions,events,ident)
    alert,_=process(Observation(ip="192.168.1.1",mac="aa:aa:aa:aa:aa:aa"),maps,Mode.monitoring,alerts,decisions,events,ident)
    assert alert is None
    assert maps["192.168.1.1"].mac==maps["192.168.1.1"].trusted_mac
    assert maps["192.168.1.1"].status=="trusted"

def test_enforcement_rejects_untrusted_new_mapping():
    maps={}; alerts=[]; decisions=[]; events=[]; n=[0]
    def ident(prefix): n[0]+=1; return f"{prefix}-{n[0]}"
    observation=Observation(ip="192.168.1.99",mac="02:de:ad:be:ef:99",unsolicited=True)
    alert,event=process(observation,maps,Mode.enforcement,alerts,decisions,events,ident)
    assert alert is not None and event.status=="alert"
    assert "192.168.1.99" not in maps and decisions[-1].action=="rejected"

def test_first_seen_mapping_is_unverified_and_later_conflict_is_flagged():
    maps={}; alerts=[]; decisions=[]; events=[]; n=[0]
    def ident(prefix): n[0]+=1; return f"{prefix}-{n[0]}"
    first=Observation(ip="192.168.1.99",mac="02:de:ad:be:ef:99")
    alert,_=process(first,maps,Mode.monitoring,alerts,decisions,events,ident)
    assert alert is None and maps[first.ip].trusted_mac is None and maps[first.ip].status=="observed"
    changed=Observation(ip=first.ip,mac="02:de:ad:be:ef:98")
    alert,_=process(changed,maps,Mode.monitoring,alerts,decisions,events,ident)
    assert alert is not None and "Conflicting" in alert.reason
    assert maps[first.ip].trusted_mac is None and maps[first.ip].status=="conflict"

def test_evaluation_metrics():
    alerts=[]; events=[]
    a,_,_,ev=run(Observation(ip="192.168.1.1",mac="bb:bb:bb:bb:bb:bb",scenario="s1",label="positive"))
    alerts.append(a); events.extend(ev)
    events += [Event(id="e2",type="arp",severity="info",status="accepted",message="ok",scenario="s2",label="negative")]
    result=evaluate(alerts,events)
    assert (result.tp,result.fp,result.fn,result.tn)==(1,0,0,1)
    assert result.precision==1 and result.recall==1 and result.latency_ms_mean is not None

def test_evaluation_zero_denominators_are_unavailable():
    result=evaluate([],[])
    assert result.precision is None and result.recall is None
    assert (result.tp,result.fp,result.fn,result.tn)==(0,0,0,0)

def test_evaluation_false_positive_and_false_negative_use_labels():
    false_positive=Event(id="e1",type="arp",severity="high",status="alert",message="unexpected",
                         scenario="negative-1",label="negative")
    missed_positive=Event(id="e2",type="arp",severity="info",status="accepted",message="missed",
                          scenario="positive-1",label="positive")
    alert=Alert(
        id="a1",severity="high",type="mapping_conflict",affected_ip="192.168.1.1",
        observed_mac="02:de:ad:be:ef:99",reason="conflicting claim",scenario="negative-1",label="negative")
    result=evaluate([alert],[false_positive,missed_positive])
    assert (result.tp,result.fp,result.fn,result.tn)==(0,1,1,0)
    assert result.precision==0 and result.recall==0
