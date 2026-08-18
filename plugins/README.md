# Custom log generator plugins

Drop a `.py` file in this directory defining an `Emitter` subclass and
ForgeIncident picks it up automatically — no packaging, no config, no fork.

```python
# plugins/zeek.py
from forge_incident.emitters import EmittedArtifact, PluginEmitter


class ZeekEmitter(PluginEmitter):
    log_source_name = "zeek"

    def emit(self, scenario):
        events = [e for e in self.relevant_events(scenario) if e.network is not None]
        if not events:
            return []
        lines = [
            f"{e.timestamp.timestamp():.6f}\t{e.network.src_ip}\t{e.network.dst_ip}"
            for e in events
        ]
        return [
            EmittedArtifact(
                relative_path="logs/zeek/conn.log",
                content="\n".join(lines) + "\n",
                description=f"Zeek conn.log ({len(events)} connections).",
            )
        ]
```

Route events to it from a scenario YAML:

```yaml
  - id: c2-beacon
    event_type: c2_beacon
    log_sources: [palo_alto]        # built-in sources
    extra:
      log_sources_extra: [zeek]     # plugin sources
```

Check what loaded:

```bash
forge-incident plugins
```

Notes:

- Files starting with `_` are skipped.
- Override this directory with `$FORGE_PLUGINS_DIR`.
- Your emitter gets the same validated `Scenario` the built-ins do, so its
  output is automatically consistent with every other log — you don't have
  to do anything to earn that.
- A plugin that fails to import or raises during `emit()` is isolated and
  reported by `forge-incident plugins`; it never breaks a generation run.
- To ship a plugin as an installable package instead, declare an entry
  point in its `pyproject.toml`:

  ```toml
  [project.entry-points."forge_incident.emitters"]
  zeek = "my_forge_plugin.zeek:ZeekEmitter"
  ```

See the "Plugins: custom log generators" section of the main README for more.
