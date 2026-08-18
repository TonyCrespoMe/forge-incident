"""Tests for the emitter plugin system.

Covers the two things that actually matter for a plugin mechanism:
a working plugin loads and runs against the same shared Scenario (so its
output correlates automatically), and a broken plugin is isolated rather
than taking down a legitimate generation run.
"""

from __future__ import annotations

from pathlib import Path

from forge_incident.emitters import BUILTIN_EMITTERS, run_all
from forge_incident.emitters.registry import (
    ENTRY_POINT_GROUP,
    PluginEmitter,
    discover_plugin_emitters,
    load_emitters,
)
from forge_incident.scenario_loader import load_scenario_from_text

_SCENARIO_YAML = """
scenario_id: plugin-test
title: "Plugin test"
description: >
  Instructor narrative.
student_briefing: >
  Investigate.
difficulty: beginner
seed: 3
organization:
  name: Testco
  domain: testco.example
start_time: "2026-05-01T09:00:00Z"
actors:
  a:
    username: u
    email: u@testco.example
    display_name: U
timeline:
  - id: e1
    at: "+0m"
    event_type: c2_beacon
    log_sources: [palo_alto]
    severity: high
    actor: a
    description: >
      Beacon to external infrastructure.
    network:
      protocol: tcp
      src_ip: 10.0.0.5
      src_port: 5000
      dst_ip: 203.0.113.9
      dst_port: 443
      action: allow
    extra:
      log_sources_extra: [zeek]
"""

_GOOD_PLUGIN = '''
"""A working example plugin: Zeek conn.log."""
from forge_incident.emitters import EmittedArtifact, PluginEmitter


class ZeekEmitter(PluginEmitter):
    log_source_name = "zeek"

    def emit(self, scenario):
        events = [e for e in self.relevant_events(scenario) if e.network is not None]
        if not events:
            return []
        lines = ["#fields\\tts\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\tproto"]
        for event in events:
            net = event.network
            lines.append(
                f"{event.timestamp.timestamp():.6f}\\t{net.src_ip}\\t{net.src_port}\\t"
                f"{net.dst_ip}\\t{net.dst_port}\\t{net.protocol.value}"
            )
        return [
            EmittedArtifact(
                relative_path="logs/zeek/conn.log",
                content="\\n".join(lines) + "\\n",
                description=f"Zeek conn.log ({len(events)} connections).",
            )
        ]
'''

_BROKEN_PLUGIN = "import a_module_that_definitely_does_not_exist\n"

_NOT_AN_EMITTER = '"""A file with no Emitter subclass in it."""\nVALUE = 1\n'

_RAISING_PLUGIN = '''
"""A plugin that loads fine but blows up during emit()."""
from forge_incident.emitters import PluginEmitter


class ExplodingEmitter(PluginEmitter):
    log_source_name = "explode"

    def emit(self, scenario):
        raise RuntimeError("boom")
'''


def _write_plugins(directory: Path, **files: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (directory / f"{name}.py").write_text(content, encoding="utf-8")
    return directory


def test_entry_point_group_name_is_stable():
    """Plugin authors declare this string in their pyproject.toml — changing
    it silently breaks every published plugin, so pin it in a test."""
    assert ENTRY_POINT_GROUP == "forge_incident.emitters"


def test_good_plugin_is_discovered_and_runs(tmp_path):
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN)
    discovery = discover_plugin_emitters(plugins_dir)

    assert not discovery.errors, discovery.errors
    assert any(name == "ZeekEmitter" for _, name in discovery.loaded)

    scenario = load_scenario_from_text(_SCENARIO_YAML, seed=3)
    artifacts = run_all(scenario, tuple(discovery.emitters))
    assert [a.relative_path for a in artifacts] == ["logs/zeek/conn.log"]


def test_plugin_output_correlates_with_builtin_output(tmp_path):
    """A plugin reads the same Event objects, so consistency is structural."""
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN)
    emitters, _ = load_emitters(BUILTIN_EMITTERS, plugins_dir=plugins_dir)

    scenario = load_scenario_from_text(_SCENARIO_YAML, seed=3)
    artifacts = {a.relative_path: a.content for a in run_all(scenario, emitters)}
    zeek = artifacts["logs/zeek/conn.log"]
    palo_alto = artifacts["logs/palo_alto/traffic.csv"]

    for identifier in ("10.0.0.5", "203.0.113.9", "5000", "443"):
        assert identifier in zeek
        assert identifier in palo_alto


def test_broken_plugin_is_isolated_not_fatal(tmp_path):
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN, broken=_BROKEN_PLUGIN)
    discovery = discover_plugin_emitters(plugins_dir)

    assert any("ZeekEmitter" == name for _, name in discovery.loaded), "good plugin must still load"
    assert any("broken.py" in origin for origin, _ in discovery.errors)
    assert any("does_not_exist" in message for _, message in discovery.errors)


def test_file_without_an_emitter_is_reported(tmp_path):
    plugins_dir = _write_plugins(tmp_path / "plugins", plain=_NOT_AN_EMITTER)
    discovery = discover_plugin_emitters(plugins_dir)
    assert not discovery.loaded
    assert any("no Emitter subclass" in message for _, message in discovery.errors)


def test_plugin_raising_during_emit_does_not_destroy_the_package(tmp_path):
    """One bad third-party emitter must not cost the user their whole run."""
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN, boom=_RAISING_PLUGIN)
    emitters, _ = load_emitters(BUILTIN_EMITTERS, plugins_dir=plugins_dir)

    scenario = load_scenario_from_text(_SCENARIO_YAML, seed=3)
    artifacts = run_all(scenario, emitters)
    paths = [a.relative_path for a in artifacts]
    assert "logs/zeek/conn.log" in paths
    assert "logs/palo_alto/traffic.csv" in paths


def test_missing_plugins_directory_is_not_an_error(tmp_path):
    discovery = discover_plugin_emitters(tmp_path / "does-not-exist")
    assert discovery.emitters == []
    assert discovery.errors == []


def test_load_emitters_puts_builtins_first(tmp_path):
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN)
    emitters, _ = load_emitters(BUILTIN_EMITTERS, plugins_dir=plugins_dir)
    assert emitters[: len(BUILTIN_EMITTERS)] == BUILTIN_EMITTERS


def test_include_plugins_false_skips_discovery_entirely(tmp_path):
    plugins_dir = _write_plugins(tmp_path / "plugins", zeek=_GOOD_PLUGIN)
    emitters, discovery = load_emitters(
        BUILTIN_EMITTERS, plugins_dir=plugins_dir, include_plugins=False
    )
    assert emitters == BUILTIN_EMITTERS
    assert discovery.loaded == []


def test_plugin_emitter_matches_only_its_own_extra_log_source():
    """PluginEmitter.relevant_events keys off extra.log_sources_extra."""

    class OtherEmitter(PluginEmitter):
        log_source_name = "something-else"

        def emit(self, scenario):
            return []

    scenario = load_scenario_from_text(_SCENARIO_YAML, seed=3)
    assert OtherEmitter().relevant_events(scenario) == []

    class ZeekLike(PluginEmitter):
        log_source_name = "zeek"

        def emit(self, scenario):
            return []

    assert len(ZeekLike().relevant_events(scenario)) == 1
