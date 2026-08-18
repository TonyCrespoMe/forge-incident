"""Streamlit web UI for ForgeIncident.

Launch with `forge-incident web` (requires `pip install "forge-incident[webui]"`).

This package deliberately contains no generation logic of its own — it is
a thin front end over the exact same `scenario_loader` / `emitters` /
`packager` / `siem` / `scoring` code paths the CLI uses, so a package built
in the browser is byte-identical to one built with `forge-incident generate`
at the same seed.
"""
