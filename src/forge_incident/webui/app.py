"""ForgeIncident Streamlit UI.

Run via `forge-incident web` (which shells out to `streamlit run` on this
file), or directly with `streamlit run .../webui/app.py`.

All the non-widget logic lives in `webui/scenario_io.py` so it can be
tested without Streamlit installed — this module is intentionally just
wiring. Every action here calls the same functions the CLI does
(`load_scenario`, `build_packages`, `export_scenario`, `score_submission`),
so a package built in the browser is byte-identical to one built on the
command line with the same seed.
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import streamlit as st

from forge_incident import __version__
from forge_incident.emitters import BUILTIN_EMITTERS, refresh_emitters
from forge_incident.models import Difficulty
from forge_incident.packager import build_packages
from forge_incident.scenario_loader import (
    ScenarioLoadError,
    list_scenarios,
    load_scenario,
    load_scenario_from_text,
)
from forge_incident.scoring import (
    SubmissionError,
    load_submission,
    render_report_markdown,
    score_submission,
)
from forge_incident.siem import EXPORTER_NAMES, export_scenario
from forge_incident.webui.scenario_io import (
    TIMELINE_COLUMNS,
    dangling_answer_key_refs,
    prune_dangling_answer_key_refs,
    raw_to_yaml,
    rows_to_timeline,
    scenario_to_raw,
    timeline_to_rows,
)

st.set_page_config(page_title="ForgeIncident", page_icon="🔍", layout="wide")

SCENARIOS_DIR = Path(os.environ.get("FORGE_SCENARIOS_DIR", "scenarios"))
OUTPUT_DIR = Path(os.environ.get("FORGE_OUTPUT_DIR", "./output"))


# --------------------------------------------------------------------------
# Session state helpers
# --------------------------------------------------------------------------


def _load_into_session(path: Path, seed: int | None = None) -> None:
    """Load a scenario file into editable session state."""
    scenario = load_scenario(path, seed=seed)
    st.session_state["raw"] = scenario_to_raw(scenario)
    st.session_state["source_path"] = str(path)
    st.session_state["loaded_scenario_id"] = scenario.scenario_id


def _current_raw() -> dict | None:
    return st.session_state.get("raw")


def _validate_current() -> tuple[object | None, str | None]:
    """Validate the in-session edited scenario. Returns (scenario, error)."""
    raw = _current_raw()
    if raw is None:
        return None, "No scenario loaded."
    try:
        return load_scenario_from_text(raw_to_yaml(raw), seed=raw.get("seed")), None
    except ScenarioLoadError as exc:
        return None, str(exc)


# --------------------------------------------------------------------------
# Sidebar: pick a scenario
# --------------------------------------------------------------------------

st.sidebar.title("🔍 ForgeIncident")
st.sidebar.caption(f"v{__version__}")

try:
    summaries = list_scenarios(SCENARIOS_DIR)
except ScenarioLoadError as exc:
    summaries = []
    st.sidebar.error(str(exc))

generated_dir = SCENARIOS_DIR / "generated"
if generated_dir.is_dir():
    try:
        summaries += list_scenarios(generated_dir)
    except ScenarioLoadError:
        pass

if summaries:
    options = {f"{s.scenario_id}  ({s.difficulty})": s.path for s in summaries}
    chosen_label = st.sidebar.selectbox("Scenario", list(options))
    chosen_path = options[chosen_label]

    seed_override = st.sidebar.number_input(
        "Seed override", min_value=0, value=0, step=1,
        help="0 = use the scenario's own declared seed.",
    )
    if st.sidebar.button("Load scenario", type="primary", use_container_width=True):
        try:
            _load_into_session(chosen_path, seed=int(seed_override) or None)
            st.sidebar.success(f"Loaded {chosen_path.name}")
        except ScenarioLoadError as exc:
            st.sidebar.error(str(exc))
else:
    st.sidebar.warning(f"No scenarios found in `{SCENARIOS_DIR}`.")

uploaded = st.sidebar.file_uploader("…or upload a scenario YAML", type=["yaml", "yml"])
if uploaded is not None and st.sidebar.button("Load uploaded file", use_container_width=True):
    try:
        scenario = load_scenario_from_text(uploaded.getvalue().decode("utf-8"))
        st.session_state["raw"] = scenario_to_raw(scenario)
        st.session_state["source_path"] = uploaded.name
        st.sidebar.success(f"Loaded {uploaded.name}")
    except ScenarioLoadError as exc:
        st.sidebar.error(str(exc))

st.sidebar.divider()
st.sidebar.caption(
    "Everything here calls the same code as the CLI — a package built in the "
    "browser is byte-identical to `forge-incident generate` at the same seed."
)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

raw = _current_raw()
if raw is None:
    st.title("ForgeIncident")
    st.info("Pick a scenario in the sidebar and click **Load scenario** to begin.")
    st.stop()

st.title(raw.get("title", "(untitled scenario)"))
scenario_obj, validation_error = _validate_current()

col_a, col_b, col_c, col_d = st.columns(4)
col_a.metric("Events", len(raw.get("timeline", [])))
col_b.metric("Actors", len(raw.get("actors", {})))
col_c.metric("Hosts", len(raw.get("hosts", {})))
col_d.metric("Seed", raw.get("seed", "—"))

if validation_error:
    st.error(f"**This scenario currently fails validation:**\n\n```\n{validation_error}\n```")
else:
    st.success("Scenario is valid.")

tab_timeline, tab_details, tab_yaml, tab_generate, tab_export, tab_score, tab_plugins = st.tabs(
    ["Timeline", "Details", "YAML", "Generate", "SIEM export", "Score", "Plugins"]
)


# -- Timeline editor --------------------------------------------------------

with tab_timeline:
    st.subheader("Timeline")
    st.caption(
        "Edit cells directly. Add a row for a new event, delete a row to remove one. "
        "`log_sources` is comma-separated. Typed payloads (process/email/network/"
        "cloud/file) are edited in the **YAML** tab — they're preserved through edits here."
    )

    rows = timeline_to_rows(raw)
    edited = st.data_editor(
        rows,
        num_rows="dynamic",
        use_container_width=True,
        column_config={
            "id": st.column_config.TextColumn("id", help="Unique event id", required=True),
            "at": st.column_config.TextColumn("at", help="Offset from start_time, e.g. +1h30m"),
            "event_type": st.column_config.TextColumn("event_type"),
            "log_sources": st.column_config.TextColumn("log_sources", help="Comma-separated"),
            "severity": st.column_config.SelectboxColumn(
                "severity", options=["info", "low", "medium", "high", "critical"]
            ),
            "actor": st.column_config.TextColumn("actor"),
            "host": st.column_config.TextColumn("host"),
            "description": st.column_config.TextColumn("description", width="large"),
        },
        column_order=TIMELINE_COLUMNS,
        key="timeline_editor",
    )

    if st.button("Apply timeline changes", type="primary"):
        updated = dict(raw)
        updated["timeline"] = rows_to_timeline(list(edited), raw.get("timeline", []))

        dangling = dangling_answer_key_refs(updated)
        if dangling:
            st.warning(
                "You deleted event(s) that the answer key points at. The references "
                "below were removed so the scenario stays valid — the questions "
                "themselves were kept:\n\n"
                + "\n".join(f"- **{qid}** → {', '.join(refs)}" for qid, refs in dangling.items())
            )
            updated = prune_dangling_answer_key_refs(updated)

        st.session_state["raw"] = updated
        st.rerun()


# -- Details ----------------------------------------------------------------

with tab_details:
    st.subheader("Scenario metadata")
    left, right = st.columns(2)
    with left:
        new_title = st.text_input("Title", raw.get("title", ""))
        new_difficulty = st.selectbox(
            "Difficulty",
            [d.value for d in Difficulty],
            index=[d.value for d in Difficulty].index(raw.get("difficulty", "intermediate")),
        )
        new_seed = st.number_input("Seed", min_value=0, value=int(raw.get("seed", 1337)), step=1)
    with right:
        org = raw.get("organization", {})
        new_org_name = st.text_input("Organization", org.get("name", ""))
        new_org_domain = st.text_input("Domain", org.get("domain", ""))
        st.caption("Keep training domains on the reserved `.example` TLD.")

    new_briefing = st.text_area(
        "Student briefing (shown to students — no spoilers)",
        raw.get("student_briefing", ""),
        height=140,
    )
    new_description = st.text_area(
        "Instructor description (full spoilers — never shown to students)",
        raw.get("description", ""),
        height=140,
    )

    if st.button("Apply metadata changes", type="primary"):
        updated = dict(raw)
        updated["title"] = new_title
        updated["difficulty"] = new_difficulty
        updated["seed"] = int(new_seed)
        updated["organization"] = {**org, "name": new_org_name, "domain": new_org_domain}
        updated["student_briefing"] = new_briefing
        updated["description"] = new_description
        st.session_state["raw"] = updated
        st.rerun()

    st.divider()
    st.subheader("Cast")
    st.write("**Actors**")
    st.json(raw.get("actors", {}), expanded=False)
    st.write("**Hosts**")
    st.json(raw.get("hosts", {}), expanded=False)
    st.caption("Actors and hosts are edited in the YAML tab.")


# -- Raw YAML ---------------------------------------------------------------

with tab_yaml:
    st.subheader("Scenario YAML")
    st.caption(
        "The full source of truth, including typed payloads. Edits here are validated "
        "before they're applied."
    )
    yaml_text = st.text_area("YAML", raw_to_yaml(raw), height=520, key="yaml_editor")

    col1, col2 = st.columns(2)
    if col1.button("Validate & apply", type="primary"):
        try:
            scenario = load_scenario_from_text(yaml_text)
            st.session_state["raw"] = scenario_to_raw(scenario)
            st.success("Valid — applied.")
            st.rerun()
        except ScenarioLoadError as exc:
            st.error(f"```\n{exc}\n```")

    col2.download_button(
        "Download YAML",
        data=raw_to_yaml(raw),
        file_name=f"{raw.get('scenario_id', 'scenario')}.yaml",
        mime="text/yaml",
        use_container_width=True,
    )

    save_path = st.text_input(
        "Save to disk as", f"{SCENARIOS_DIR}/{raw.get('scenario_id', 'scenario')}.yaml"
    )
    if st.button("Save to disk"):
        if validation_error:
            st.error("Fix the validation error before saving.")
        else:
            target = Path(save_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(raw_to_yaml(raw), encoding="utf-8")
            st.success(f"Wrote {target}")


# -- Generate ---------------------------------------------------------------

with tab_generate:
    st.subheader("Generate training packages")
    if validation_error:
        st.error("Scenario must be valid before generating. See the error above.")
    else:
        st.write(
            f"Renders **{len(raw.get('timeline', []))} events** through every registered "
            "log emitter, then builds the student and instructor ZIPs."
        )
        if st.button("Generate packages", type="primary"):
            with st.spinner("Rendering logs and building packages…"):
                result = build_packages(scenario_obj, OUTPUT_DIR, source_path=None)
            st.success(
                f"Built {result.artifact_count} log artifact(s) → `{result.student_zip}` and "
                f"`{result.instructor_zip}`"
            )
            st.session_state["last_result"] = {
                "student": str(result.student_zip),
                "instructor": str(result.instructor_zip),
            }

        last = st.session_state.get("last_result")
        if last:
            c1, c2 = st.columns(2)
            for column, (label, path_str) in zip((c1, c2), last.items(), strict=False):
                path = Path(path_str)
                if path.is_file():
                    column.download_button(
                        f"Download {label} ZIP",
                        data=path.read_bytes(),
                        file_name=path.name,
                        mime="application/zip",
                        use_container_width=True,
                    )
            student_path = Path(last["student"])
            if student_path.is_file():
                with st.expander("Preview student package contents"):
                    with zipfile.ZipFile(student_path) as zf:
                        for name in zf.namelist():
                            st.write(f"`{name}`")
                        preview = st.selectbox("Preview file", zf.namelist())
                        if preview:
                            st.code(
                                zf.read(preview).decode("utf-8", errors="replace")[:5000],
                                language=None,
                            )


# -- SIEM export ------------------------------------------------------------

with tab_export:
    st.subheader("Export to a SIEM")
    st.caption(
        "Load a scenario straight into Splunk, Elastic, or Microsoft Sentinel and run "
        "the exercise inside the tool students actually use."
    )
    if validation_error:
        st.error("Scenario must be valid before exporting.")
    else:
        chosen_formats = st.multiselect(
            "Formats", list(EXPORTER_NAMES), default=list(EXPORTER_NAMES)
        )
        if st.button("Export", type="primary") and chosen_formats:
            artifacts = export_scenario(scenario_obj, chosen_formats)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for artifact in artifacts:
                    zf.writestr(artifact.relative_path, artifact.content)
            st.success(f"Exported {len(artifacts)} file(s).")
            st.download_button(
                "Download SIEM export bundle",
                data=buffer.getvalue(),
                file_name=f"{raw.get('scenario_id', 'scenario')}-siem-export.zip",
                mime="application/zip",
            )
            for artifact in artifacts:
                with st.expander(artifact.relative_path):
                    st.caption(artifact.description)
                    st.code(artifact.content[:3000], language=None)


# -- Score ------------------------------------------------------------------

with tab_score:
    st.subheader("Score a student submission")
    st.caption(
        "Upload a completed `submission.json` from a student package. Scoring is "
        "deterministic — make sure the seed matches the package they worked from."
    )
    if validation_error:
        st.error("Scenario must be valid before scoring against it.")
    else:
        submission_file = st.file_uploader("submission.json", type=["json", "yaml", "yml"])
        if submission_file is not None:
            tmp = OUTPUT_DIR / "_uploaded_submission.json"
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(submission_file.getvalue())
            try:
                submission = load_submission(tmp)
            except SubmissionError as exc:
                st.error(str(exc))
            else:
                report = score_submission(scenario_obj, submission)
                m1, m2, m3 = st.columns(3)
                m1.metric(
                    "Detection coverage",
                    f"{report.coverage_pct:.0f}%",
                    f"{report.detected_count}/{report.total_opportunities}",
                )
                m2.metric(
                    "Precision",
                    f"{report.precision_pct:.0f}%",
                    f"-{report.false_positive_count + report.unknown_event_id_count} FP",
                    delta_color="inverse",
                )
                ttfd = report.time_to_first_detection_seconds
                m3.metric(
                    "Time to first detection",
                    "n/a" if ttfd is None else f"{ttfd / 60:.0f} min",
                )

                st.write("**Coverage by ATT&CK tactic**")
                st.dataframe(
                    [
                        {
                            "Tactic": tactic,
                            "Detected": found,
                            "Total": total,
                            "Coverage %": round(100 * found / total, 1) if total else 0.0,
                        }
                        for tactic, (found, total) in sorted(report.coverage_by_tactic.items())
                    ],
                    use_container_width=True,
                    hide_index=True,
                )

                report_md = render_report_markdown(report, scenario_obj)
                with st.expander("Full report"):
                    st.markdown(report_md)
                d1, d2 = st.columns(2)
                d1.download_button(
                    "Download report (Markdown)",
                    data=report_md,
                    file_name=f"{scenario_obj.scenario_id}-score.md",
                    use_container_width=True,
                )
                d2.download_button(
                    "Download report (JSON)",
                    data=json.dumps(report.to_dict(), indent=2),
                    file_name=f"{scenario_obj.scenario_id}-score.json",
                    use_container_width=True,
                )


# -- Plugins ----------------------------------------------------------------

with tab_plugins:
    st.subheader("Log generators")
    plugins_dir = st.text_input(
        "Plugins directory", os.environ.get("FORGE_PLUGINS_DIR", "plugins")
    )
    if st.button("Rescan plugins"):
        st.session_state["discovery"] = refresh_emitters(plugins_dir=plugins_dir)

    discovery = st.session_state.get("discovery") or refresh_emitters(plugins_dir=plugins_dir)

    st.write(f"**Built-in ({len(BUILTIN_EMITTERS)})**")
    st.dataframe(
        [
            {
                "Log source": getattr(e, "log_source").value,
                "Class": type(e).__name__,
            }
            for e in BUILTIN_EMITTERS
        ],
        use_container_width=True,
        hide_index=True,
    )

    if discovery.loaded:
        st.write(f"**Plugins ({len(discovery.loaded)})**")
        st.dataframe(
            [{"Class": name, "Loaded from": origin} for origin, name in discovery.loaded],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info(
            f"No plugins found in `{plugins_dir}`. Drop in a `.py` file defining an "
            "`Emitter` subclass — see CONTRIBUTING.md."
        )

    if discovery.errors:
        st.error("**Plugins that failed to load**")
        for origin, message in discovery.errors:
            st.write(f"- `{origin}`: {message}")
