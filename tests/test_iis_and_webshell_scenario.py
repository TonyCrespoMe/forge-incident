"""Tests for the IIS emitter and the web-shell-to-DC-compromise scenario.

The scenario is built around three teaching devices, and each of them is
only a teaching device if it actually holds in the rendered output. These
tests pin all three, because a silent regression would quietly turn the
hardest bundled scenario into a much easier one:

1. Web-shell commands are base64-encoded in the query string.
2. Two DC-side actions have NO web-log counterpart (the POST visibility gap).
3. The LSASS dump is not just created and renamed, but retrieved.
"""

from __future__ import annotations

import base64
import re

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.emitters.iis import IisEmitter
from forge_incident.models import LogSource
from forge_incident.scenario_loader import load_scenario, load_scenario_from_text
from tests.conftest import SCENARIOS_DIR

SCENARIO_FILE = SCENARIOS_DIR / "webshell_to_dc_compromise.yaml"


def _artifacts(scenario):
    return {a.relative_path: a.content for a in run_all(scenario, BUILTIN_EMITTERS)}


def _iis_log(artifacts) -> str:
    return next(c for p, c in artifacts.items() if "/iis/" in p)


# --------------------------------------------------------------------------
# IIS emitter format
# --------------------------------------------------------------------------

_MINIMAL = """
scenario_id: iis-format-test
title: "IIS format test"
description: >
  Instructor narrative.
student_briefing: >
  Investigate.
difficulty: beginner
seed: 4
organization:
  name: Testco
  domain: testco.example
start_time: "2025-06-01T14:00:00Z"
actors:
  attacker:
    username: unknown
    email: unknown@unknown.external
    display_name: Unknown
hosts:
  web:
    hostname: WEB
    ip_address: 10.0.0.9
    host_type: server
    os: windows
timeline:
  - id: plain
    at: "+0m"
    event_type: web_request
    log_sources: [iis]
    severity: info
    host: web
    description: A plain request with no query string.
    http:
      method: GET
      uri_stem: /index.aspx
      status_code: 200
      time_taken_ms: 12
  - id: withquery
    at: "+1m"
    event_type: web_request
    log_sources: [iis]
    severity: low
    host: web
    description: A request carrying a query string.
    http:
      method: GET
      uri_stem: /search.aspx
      uri_query: "q=widget&page=2"
      status_code: 404
      substatus: 2
      win32_status: 3
      time_taken_ms: 88
  - id: posted
    at: "+2m"
    event_type: web_shell_command
    log_sources: [iis]
    severity: high
    host: web
    description: A POST carrying a command in the body, which IIS never logs.
    http:
      method: POST
      uri_stem: /shell.aspx
      cmd_plaintext: "net user"
      status_code: 200
      time_taken_ms: 5
"""


def _minimal_log() -> str:
    scenario = load_scenario_from_text(_MINIMAL, seed=4)
    return IisEmitter().emit(scenario)[0].content


def test_iis_log_has_the_w3c_header_block():
    content = _minimal_log()
    lines = content.splitlines()
    assert lines[0].startswith("#Software: Microsoft Internet Information Services")
    assert lines[1] == "#Version: 1.0"
    assert lines[2].startswith("#Date: ")
    assert lines[3].startswith("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query")


def test_iis_field_count_is_constant_even_when_fields_are_empty():
    """W3C uses '-' for empty, never a missing column. If this regresses,
    every field-position-based parse of the log silently shifts."""
    content = _minimal_log()
    data_lines = [x for x in content.splitlines() if not x.startswith("#")]
    field_count = len(content.splitlines()[3].replace("#Fields: ", "").split())
    for line in data_lines:
        assert len(line.split(" ")) == field_count, line


def test_absent_query_string_renders_as_hyphen():
    line = next(x for x in _minimal_log().splitlines() if "/index.aspx" in x)
    assert " /index.aspx - " in line


def test_user_agent_spaces_are_escaped_as_plus_like_real_iis():
    line = next(x for x in _minimal_log().splitlines() if "/index.aspx" in x)
    assert "Mozilla/5.0+(Windows" in line
    # And no raw space inside the agent, which would break field counting.
    assert "Mozilla/5.0 (" not in line


def test_status_substatus_and_win32_status_are_separate_fields():
    line = next(x for x in _minimal_log().splitlines() if "/search.aspx" in x)
    fields = line.split(" ")
    assert fields[-4:] == ["404", "2", "3", "88"]


def test_post_requests_never_leak_the_command_into_the_log():
    """The core visibility-gap mechanic: a command sent by POST lives in the
    request body, and IIS does not log bodies."""
    content = _minimal_log()
    posted = next(x for x in content.splitlines() if "/shell.aspx" in x)
    assert "cmd=" not in posted
    assert base64.b64encode(b"net user").decode() not in content
    assert "net+user" not in content


def test_get_borne_commands_are_base64_encoded_not_cleartext():
    scenario = load_scenario(SCENARIO_FILE)
    content = _iis_log(_artifacts(scenario))
    assert "cmd=whoami" not in content
    decoded = [
        base64.b64decode(m + "===").decode("utf-8", errors="replace")
        for m in re.findall(r"cmd=([A-Za-z0-9+/=]+)", content)
    ]
    assert "whoami" in decoded
    assert any("wmiutil.exe" in d for d in decoded)
    assert any("Invoke-SMBExec" in d for d in decoded)


def test_iis_filename_follows_the_hourly_convention():
    scenario = load_scenario(SCENARIO_FILE)
    paths = [p for p in _artifacts(scenario) if "/iis/" in p]
    assert len(paths) == 1
    assert re.fullmatch(r"logs/iis/u_ex\d{8}\.log", paths[0]), paths[0]


# --------------------------------------------------------------------------
# The scenario's three teaching devices
# --------------------------------------------------------------------------


def test_scenario_loads_and_covers_both_hosts():
    scenario = load_scenario(SCENARIO_FILE)
    assert scenario.event_count >= 25
    assert len(scenario.answer_key) >= 8
    paths = _artifacts(scenario)
    assert any("/iis/" in p for p in paths)
    assert any("appsrv-02" in p for p in paths)
    assert any("dc-core-01" in p for p in paths)


def test_the_post_visibility_gap_actually_holds():
    """Two DC actions must be invisible in the web log. If a future edit
    routes them to `iis` as well, the scenario loses its hardest lesson."""
    scenario = load_scenario(SCENARIO_FILE)
    artifacts = _artifacts(scenario)
    iis = _iis_log(artifacts)
    dc = next(c for p, c in artifacts.items() if "dc-core-01" in p)

    for event_id in ("dc-recon-whoami", "dc-recon-hostname"):
        event = next(e for e in scenario.timeline if e.event_id == event_id)
        assert LogSource.IIS not in event.log_sources
        assert event.service is not None
        assert event.service.service_name in dc, "gap event must be visible on the DC"
        assert event.service.service_name not in iis, "gap event must NOT be in the web log"


def test_exfiltration_is_a_retrieval_not_just_a_rename():
    """The dump must be downloaded, not merely created and renamed --
    that distinction is what answer_key q4 grades."""
    scenario = load_scenario(SCENARIO_FILE)
    iis = _iis_log(_artifacts(scenario))
    exfil = next(x for x in iis.splitlines() if "/portal/assets/banner-hero.jpg" in x)
    fields = exfil.split(" ")
    assert fields[3] == "GET"
    assert "200" in fields
    assert "98432" in fields, "the long transfer time is part of the evidence"


def test_dump_hash_is_identical_before_and_after_the_rename():
    """Masquerading changes the name, never the content -- so the hash must
    match across dump, rename, and exfil for students to link them."""
    scenario = load_scenario(SCENARIO_FILE)
    by_id = {e.event_id: e for e in scenario.timeline}
    hashes = {
        by_id[eid].file.sha256
        for eid in ("lsass-dump", "masquerade-dump", "exfil-dump")
        if by_id[eid].file
    }
    assert len(hashes) == 1, f"expected one shared hash, got {hashes}"


def test_all_six_service_installs_render_as_7045():
    scenario = load_scenario(SCENARIO_FILE)
    dc = next(c for p, c in _artifacts(scenario).items() if "dc-core-01" in p)
    names = re.findall(r'<Data Name="ServiceName">([^<]+)</Data>', dc)
    assert len(names) == 6
    for name in names:
        assert re.fullmatch(r"[A-Z]{20}", name), f"{name} should be a random 20-char upper name"
    assert dc.count("<EventID>7045</EventID>") == 6


def test_pass_the_hash_lands_as_an_ntlm_logon_on_the_dc():
    scenario = load_scenario(SCENARIO_FILE)
    event = next(e for e in scenario.timeline if e.event_id == "dc-ntlm-logon")
    assert event.extra["authentication_package"] == "NTLM"
    assert event.extra["logon_type"] == 3
    assert event.host == "dccore01"


def test_the_stolen_hash_is_identical_everywhere_it_appears():
    scenario = load_scenario(SCENARIO_FILE)
    blob = "\n".join(a.content for a in run_all(scenario, BUILTIN_EMITTERS))
    assert blob.count("3ba61d9c7f04e28a5c6d13804f9ae7b2") >= 2


def test_no_scanner_user_agents_so_students_must_hunt_by_path():
    """The scenario deliberately contains no curl/nikto/sqlmap agents --
    the intrusion is only findable through anomalous paths."""
    scenario = load_scenario(SCENARIO_FILE)
    iis = _iis_log(_artifacts(scenario)).lower()
    for agent in ("sqlmap", "nikto", "curl/", "python-requests", "wget/"):
        assert agent not in iis
