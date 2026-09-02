"""Tests for the bundled sql_injection_data_breach.yaml scenario.

The scenario's central claim is that response size, not status code or
user-agent, is the signal that separates ordinary traffic to a mundane
endpoint from an active SQL injection dump. These tests confirm that claim
actually holds in the rendered artifacts a student receives -- both the
IIS access log (sc-bytes) and the firewall log (Bytes Sent) -- not just in
the scenario's prose.
"""

from __future__ import annotations

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.scenario_loader import load_scenario
from tests.conftest import SCENARIOS_DIR

SCENARIO_FILE = SCENARIOS_DIR / "sql_injection_data_breach.yaml"

_ATTACKER_IP = "192.0.2.77"


def _artifacts(scenario):
    return {a.relative_path: a.content for a in run_all(scenario, BUILTIN_EMITTERS)}


def _log(artifacts, source: str) -> str:
    return next(c for p, c in artifacts.items() if f"/{source}/" in p)


def test_scenario_loads():
    scenario = load_scenario(SCENARIO_FILE)
    assert scenario.scenario_id == "sql-injection-data-breach-01"


def test_every_malicious_request_uses_an_ordinary_browser_user_agent():
    """No scanner/tool signature anywhere -- the whole point is that the
    query CONTENT is the only tell, not who's asking."""
    scenario = load_scenario(SCENARIO_FILE)
    iis = _log(_artifacts(scenario), "iis")
    banned_tokens = ("sqlmap", "curl/", "python-requests", "nikto", "nmap")
    lowered = iis.lower()
    for token in banned_tokens:
        assert token not in lowered


def test_injection_payloads_are_fully_plaintext_not_encoded():
    """Contrast with A3 (webshell_to_dc_compromise): nothing here is
    base64'd or obfuscated. If this scenario's payloads ever became
    encoded, its central lesson -- that the difficulty is entirely about
    actually reading the query string -- would be lost."""
    scenario = load_scenario(SCENARIO_FILE)
    iis = _log(_artifacts(scenario), "iis")
    assert "UNION+SELECT" in iis
    assert "stored_payment_methods" in iis
    assert "admin_users" in iis


def test_response_size_escalates_sharply_at_the_two_dumps():
    """sc-bytes must show the actual scale difference: a normal lookup
    (~2KB), the boolean-true probe (~180KB), and the payment-card dump
    (multiple MB) -- in that ascending order, with the final value orders
    of magnitude larger than anything else in the log."""
    scenario = load_scenario(SCENARIO_FILE)
    iis = _log(_artifacts(scenario), "iis")
    lines = [x for x in iis.splitlines() if not x.startswith("#")]

    def sc_bytes(needle: str) -> int:
        line = next(x for x in lines if needle in x)
        return int(line.split(" ")[-1])

    normal = sc_bytes("code=7F3KQ92M")
    boolean_probe = sc_bytes("OR+'1'='1")
    admin_dump = sc_bytes("admin_users")
    card_dump = sc_bytes("stored_payment_methods")

    assert normal < 5_000
    assert boolean_probe > normal * 20
    assert admin_dump > normal
    assert card_dump > admin_dump * 100, (
        "the payment-card dump must dwarf every other request -- that scale "
        "gap is the scenario's core evidence"
    )


def test_firewall_log_shows_the_same_volume_spike_as_the_web_log():
    """Cross-source correlation: the same three requests must show a
    consistent, escalating Bytes Sent in the Palo Alto traffic log too --
    not just in IIS. A student working only from the firewall log should
    reach the same conclusion."""
    scenario = load_scenario(SCENARIO_FILE)
    palo_alto = _log(_artifacts(scenario), "palo_alto")
    lines = [x for x in palo_alto.splitlines() if x.strip() and "Receive Time" not in x]
    header = next(x for x in palo_alto.splitlines() if "Receive Time" in x).split(",")
    bytes_sent_idx = header.index("Bytes Sent")

    card_dump_line = next(x for x in lines if x.split(",")[bytes_sent_idx] == "4180224")
    assert _ATTACKER_IP in card_dump_line


def test_benign_lookups_never_carry_the_attacker_ip():
    scenario = load_scenario(SCENARIO_FILE)
    scenario_obj = scenario
    benign_ids = {
        e.event_id
        for e in scenario_obj.timeline
        if e.event_id.startswith("benign-")
    }
    for event in scenario_obj.timeline:
        if event.event_id in benign_ids and event.network is not None:
            assert event.network.src_ip != _ATTACKER_IP


def test_admin_dump_precedes_payment_card_dump():
    """The scenario's two-act structure matters: a student who stops
    investigating after the first (bad but lesser) finding must be shown
    to have understated the breach, which only holds if the order is
    admin credentials, then payment cards -- not the reverse."""
    scenario = load_scenario(SCENARIO_FILE)
    by_id = {e.event_id: e for e in scenario.timeline}
    assert by_id["dump-admin-credentials"].timestamp < by_id["dump-payment-cards"].timestamp
