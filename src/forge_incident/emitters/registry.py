"""Emitter registry and plugin discovery.

ForgeIncident ships a fixed set of built-in emitters (see
`emitters/__init__.py`'s `BUILTIN_EMITTERS`). This module lets third
parties add their own log formats *without forking the project*, via two
independent mechanisms:

1. **Installed packages**, using a setuptools entry point group named
   `forge_incident.emitters`. A plugin package declares, in its own
   `pyproject.toml`:

       [project.entry-points."forge_incident.emitters"]
       zeek = "my_forge_plugin.zeek:ZeekEmitter"

   ...and once that package is `pip install`ed into the same environment,
   `forge-incident` picks it up automatically with no config.

2. **A local plugins directory** (default `./plugins/`, override with
   `$FORGE_PLUGINS_DIR`), for the much more common case of "I just want
   one extra log format for my own course and don't want to package it."
   Every `*.py` file in that directory is imported and scanned for
   `Emitter` subclasses. This is the zero-ceremony path — drop a file in,
   it works.

Both paths converge on the same contract: a plugin is just a subclass of
`emitters.base.Emitter` with a `log_source` class attribute and an
`emit(scenario) -> list[EmittedArtifact]` method. Plugins get the exact
same validated `Scenario` the built-ins do, which means a plugin's output
is automatically consistent with every built-in log — the shared-event
guarantee is structural, not something a plugin author has to remember.

Failure policy: a broken plugin must never take down a legitimate
generation run. Import errors and bad classes are collected into
`DiscoveryResult.errors` and surfaced by `forge-incident plugins`, while
the built-ins (and every healthy plugin) still load and run.

Custom log sources
------------------
`models.LogSource` is a closed enum, so a plugin targeting a format
ForgeIncident doesn't know about can't add a new member to it. Instead a
plugin may set `log_source_name` (a plain string) and route events using
`Event.extra["log_sources_extra"]` — see `PluginEmitter` below, which
implements exactly that and is the recommended base class for plugins
covering a format outside the built-in enum.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from forge_incident.emitters.base import Emitter
from forge_incident.models import Event, Scenario

__all__ = [
    "ENTRY_POINT_GROUP",
    "DEFAULT_PLUGINS_DIR",
    "DiscoveryResult",
    "PluginEmitter",
    "discover_plugin_emitters",
    "load_emitters",
]

ENTRY_POINT_GROUP = "forge_incident.emitters"
DEFAULT_PLUGINS_DIR = "plugins"


class PluginEmitter(Emitter):
    """Convenience base class for plugins targeting a NON-built-in log source.

    `models.LogSource` is a closed enum that a plugin can't extend, so
    instead of setting `log_source`, a plugin subclasses this and sets
    `log_source_name`:

        class ZeekEmitter(PluginEmitter):
            log_source_name = "zeek"

            def emit(self, scenario):
                for event in self.relevant_events(scenario):
                    ...

    Scenario authors then route events to it by adding the name to
    `extra.log_sources_extra`, alongside the normal `log_sources:` list:

        - id: c2-beacon
          event_type: c2_beacon
          log_sources: [palo_alto]        # built-in sources, as usual
          extra:
            log_sources_extra: [zeek]     # plugin sources

    `relevant_events` is overridden here to match on that field, so a
    plugin author implements `emit()` exactly like a built-in emitter
    and nothing else changes.
    """

    log_source_name: str = ""

    def relevant_events(self, scenario: Scenario) -> list[Event]:
        name = self.log_source_name
        if not name:
            return []
        return [
            event
            for event in scenario.timeline
            if name in (event.extra.get("log_sources_extra") or [])
        ]


@dataclass
class DiscoveryResult:
    """What plugin discovery found — and what went wrong, if anything."""

    emitters: list[Emitter] = field(default_factory=list)
    #: (source_description, error_message) for anything that failed to load.
    errors: list[tuple[str, str]] = field(default_factory=list)
    #: (source_description, class_name) for everything loaded successfully.
    loaded: list[tuple[str, str]] = field(default_factory=list)


def _instantiate(candidate: type, origin: str, result: DiscoveryResult) -> None:
    try:
        instance = candidate()
    except Exception as exc:  # a plugin's __init__ can raise anything
        result.errors.append((origin, f"{candidate.__name__} could not be instantiated: {exc}"))
        return

    has_builtin_source = getattr(instance, "log_source", None) is not None
    has_plugin_source = bool(getattr(instance, "log_source_name", ""))
    if not (has_builtin_source or has_plugin_source):
        result.errors.append(
            (
                origin,
                f"{candidate.__name__} sets neither 'log_source' (a models.LogSource) nor "
                "'log_source_name' (a string, for PluginEmitter subclasses) — skipped.",
            )
        )
        return

    result.emitters.append(instance)
    result.loaded.append((origin, candidate.__name__))


def _emitter_classes_in_module(module) -> list[type]:
    """Every concrete Emitter subclass *defined in* this module.

    Filtering on `__module__` matters: a plugin file that does
    `from forge_incident.emitters.base import Emitter` (or imports a
    built-in emitter for reference) shouldn't accidentally re-register
    the imported class.
    """
    found = []
    for _, obj in inspect.getmembers(module, inspect.isclass):
        if not issubclass(obj, Emitter) or obj in (Emitter, PluginEmitter):
            continue
        if obj.__module__ != module.__name__:
            continue
        if inspect.isabstract(obj):
            continue
        found.append(obj)
    return found


def _discover_entry_point_emitters(result: DiscoveryResult) -> None:
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover - Python < 3.8 only
        return

    try:
        # Python 3.10+ selectable API.
        selected = entry_points(group=ENTRY_POINT_GROUP)
    except TypeError:  # pragma: no cover - very old importlib.metadata
        selected = entry_points().get(ENTRY_POINT_GROUP, [])  # type: ignore[union-attr]

    for entry_point in selected:
        origin = f"entry-point:{entry_point.name}"
        try:
            candidate = entry_point.load()
        except Exception as exc:
            result.errors.append((origin, f"failed to import: {exc}"))
            continue
        if not (inspect.isclass(candidate) and issubclass(candidate, Emitter)):
            result.errors.append(
                (origin, f"{candidate!r} is not a subclass of forge_incident.emitters.base.Emitter")
            )
            continue
        _instantiate(candidate, origin, result)


def _discover_directory_emitters(plugins_dir: Path, result: DiscoveryResult) -> None:
    if not plugins_dir.is_dir():
        return

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue
        origin = f"file:{path}"
        module_name = f"forge_incident_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                result.errors.append((origin, "could not build an import spec for this file"))
                continue
            module = importlib.util.module_from_spec(spec)
            # Register before exec so dataclasses/pickle inside the plugin resolve.
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as exc:
            sys.modules.pop(module_name, None)
            result.errors.append((origin, f"failed to import: {exc}"))
            continue

        classes = _emitter_classes_in_module(module)
        if not classes:
            result.errors.append(
                (origin, "no Emitter subclass defined in this file — nothing to register")
            )
            continue
        for candidate in classes:
            _instantiate(candidate, origin, result)


def discover_plugin_emitters(plugins_dir: str | Path | None = None) -> DiscoveryResult:
    """Find every plugin emitter, from both entry points and a local directory.

    `plugins_dir` defaults to `$FORGE_PLUGINS_DIR`, then `./plugins`.
    Never raises: problems are reported in `DiscoveryResult.errors`.
    """
    result = DiscoveryResult()
    _discover_entry_point_emitters(result)

    resolved = plugins_dir or os.environ.get("FORGE_PLUGINS_DIR") or DEFAULT_PLUGINS_DIR
    _discover_directory_emitters(Path(resolved), result)
    return result


def load_emitters(
    builtins: tuple[Emitter, ...],
    *,
    plugins_dir: str | Path | None = None,
    include_plugins: bool = True,
) -> tuple[tuple[Emitter, ...], DiscoveryResult]:
    """Built-in emitters plus any discovered plugins, and the discovery report.

    Built-ins always come first so their output ordering is stable
    regardless of what plugins happen to be installed.
    """
    if not include_plugins:
        return builtins, DiscoveryResult()
    result = discover_plugin_emitters(plugins_dir)
    return (*builtins, *result.emitters), result
