"""Present recorded Android runtime evidence without inventing source locations.

Device access, capture persistence and import validation belong to the caller. This
panel renders only capture records supplied by those services.
"""
from __future__ import annotations

import json
import math
from typing import Any, Callable, Mapping, Sequence

import pandas as pd
import streamlit as st

from ..models import ScanResult
from ..walker import strip_bidi
from . import decoded_panel

Text = Callable[[str], str]
KINDS = {"url": "Runtime URL", "host": "Runtime host", "credential": "Credential candidate",
         "crypto_key": "Observed encryption key", "connection": "Socket destination attempt"}
STATUS = {"completed": "Capture completed", "partial": "Partial capture", "failed": "Capture failed",
          "running": "Capture running", "imported_external": "Imported capture"}
PROFILES = {"startup": "Startup instrumentation", "attached_process": "Attached running process",
            "warm_launch_attach": "Attached after launch"}
MAX_IMPORT_BYTES = 64 << 20
CAPTURE_ACTIVE = "runtime_capture_in_progress"


def _plain(value: Any) -> str:
    return strip_bidi(str(value if value is not None else ""))


def _records(value: Any) -> list[Mapping]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, (list, tuple)) else []


def _pick_row(grid_key: str, selected_key: str, indices: Sequence[int]) -> None:
    state = st.session_state.get(grid_key) or {}
    selection = state.get("selection", {}) if isinstance(state, Mapping) else getattr(state, "selection", {})
    rows = selection.get("rows", ()) if isinstance(selection, Mapping) else getattr(selection, "rows", ())
    if rows and type(rows[0]) is int and 0 <= rows[0] < len(indices):
        st.session_state[selected_key] = indices[rows[0]]


def _verified_locations(item: Mapping, result: ScanResult | None) -> list[Mapping]:
    """Validate claimed literal matches against the actual retained source snapshot."""
    if result is None:
        return []
    value = item.get("value")
    if not isinstance(value, str) or not value:
        return []
    found = []
    for location in _records(item.get("locations")):
        path, line = location.get("file"), location.get("line")
        if not location.get("verified") or location.get("relation") != "exact_literal":
            continue
        file = result.decoded_files.get(path) if isinstance(path, str) else None
        if file is None or type(line) is not int or not 1 <= line <= len(file.lines):
            continue
        column, end = location.get("column", 0), location.get("end_column", 0)
        source = file.lines[line - 1]
        if type(column) is int and column > 0:
            if type(end) is int and end > column and source[column - 1:end - 1] == value:
                found.append(location)
            elif source[column - 1:column - 1 + len(value)] == value:
                found.append({**location, "end_column": column + len(value)})
        elif value in source:
            column = source.index(value) + 1
            found.append({**location, "column": column, "end_column": column + len(value)})
    return found


def _evidence_event(capture: Mapping, item: Mapping) -> tuple[int, Mapping | None]:
    events = _records(capture.get("events"))
    evidence = item.get("evidence") or {}
    line = evidence.get("line") if isinstance(evidence, Mapping) else None
    if type(line) is int and 1 <= line <= len(events):
        return line, events[line - 1]
    ids = item.get("event_ids") or []
    for number, event in enumerate(events, 1):
        if event.get("id") in ids or event.get("event_id") in ids:
            return number, event
    return 0, None


def _render_observation(result: ScanResult | None, capture: Mapping, item: Mapping, t: Text,
                        prefix: str, on_open_source: Callable[[str, int], None] | None) -> None:
    with st.container(border=True):
        st.subheader(t("Runtime evidence"))
        st.caption(t(KINDS.get(str(item.get("kind")), "Observed value")))
        st.code(_plain(item.get("value")), language="text")
        if len(_records(item.get("evidence_locations"))) > 1:
            st.caption(t("Summary metadata describes the first occurrence. Select another recorded "
                         "event below to inspect its own timestamp, API and call stack."))
        metadata = [("Observed at", item.get("timestamp")), ("Observed API", item.get("api")),
                    ("Process ID", item.get("pid")), ("Thread ID", item.get("tid")),
                    ("Observation label", item.get("label")), ("Recorded occurrences", item.get("occurrence_count"))]
        for label, value in metadata:
            if value not in (None, ""):
                st.text(f"{t(label)}: {_plain(value)}")
        if item.get("kind") in {"credential", "crypto_key"}:
            st.caption(t("Observed key material or a token-shaped value does not by itself prove "
                         "a credential leak or exploitability."))
        if item.get("details"):
            with st.expander(t("Observation details")):
                st.json(item["details"])

        locations = _verified_locations(item, result)
        if locations:
            st.caption(t("Exact value match in the retained files. This does not prove that this "
                         "line generated the runtime value."))
            labels = {i: f"{_plain(location['file'])}:{location['line']}:{location.get('column', 1)}"
                      for i, location in enumerate(locations)}
            selected = st.selectbox(t("Matching file location"), list(labels), format_func=labels.get,
                                    key=prefix + "_location") if len(labels) > 1 else 0
            location = locations[selected]
            if on_open_source is not None:
                decoded_panel.render_location(
                    location["file"], location["line"], result.decoded_files[location["file"]],
                    t, on_open=on_open_source, key=prefix + "_open", focus=str(item["value"]),
                    column=location.get("column", 0), end_column=location.get("end_column", 0),
                    member=result.app.get("apk_file_members", {}).get(location["file"], ""))
            else:
                st.code(labels[selected], language="text")
        else:
            st.info(t("No exact source line was verified for this value. Its runtime event and "
                      "recorded call stack are shown below."))
        inferred = [location for location in _records(item.get("locations"))
                    if location.get("relation") == "class_method"]
        if inferred:
            with st.expander(t("Related class or method candidates")):
                st.caption(t("These are possible code associations, not verified source lines."))
                st.json(inferred)

        stack = _records(item.get("stack"))
        with st.expander(t("Recorded call stack"), expanded=not locations):
            if stack:
                rows = [{t("Class / module"): _plain(frame.get("class_name") or frame.get("module")),
                         t("Method / address"): _plain(frame.get("method") or frame.get("address")),
                         t("Runtime source file"): _plain(frame.get("file_name")),
                         t("Runtime line"): frame.get("line", "")} for frame in stack]
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
                st.caption(t("Runtime stack line numbers are debug metadata; they are not JADX "
                             "line numbers."))
            else:
                st.caption(t("No call stack was recorded for this event."))
        line, event = _evidence_event(capture, item)
        evidence = item.get("evidence") or {}
        occurrences = _records(item.get("evidence_locations"))
        if len(occurrences) > 1:
            options = {i: f"{_plain(record.get('file'))}:{record.get('line')}"
                       for i, record in enumerate(occurrences)}
            selected = st.selectbox(t("Recorded event occurrence"), list(options), format_func=options.get,
                                    key=prefix + "_occurrence")
            evidence = occurrences[selected]
            line, event = _evidence_event(capture, {**item, "evidence": evidence})
        if event is not None:
            path = evidence.get("file") if isinstance(evidence, Mapping) else ""
            st.caption(t("Capture record: %s · line %d") % (_plain(path or "events.jsonl"), line))
            st.caption(t("This line belongs to the capture log, not to the application's source code."))
            st.code(json.dumps(event, ensure_ascii=False, indent=2), language="json")
        else:
            st.warning(t("The referenced runtime event is unavailable in this capture."))


def _render_capture(result: ScanResult | None, capture: Mapping, t: Text, prefix: str,
                    on_open_source: Callable[[str, int], None] | None) -> None:
    status = str(capture.get("status", ""))
    label = t(STATUS.get(status, "Capture status unavailable"))
    if status == "failed":
        st.error(label)
    elif status in {"partial", "running"}:
        st.warning(label)
    else:
        st.caption(label)
    st.text(f"{t('Target package')}: {_plain(capture.get('package'))}")
    st.caption(t("Device: %s · started: %s · ended: %s") % (
        _plain(capture.get("serial")), _plain(capture.get("started_at")), _plain(capture.get("ended_at"))))
    imported = bool(capture.get("imported_external")) or status == "imported_external"
    if imported:
        st.info(t("Imported evidence: this dashboard did not independently witness the capture."))
    events, observations = _records(capture.get("events")), _records(capture.get("observations"))
    counts = [len(events), sum(x.get("kind") in {"url", "host", "connection"} for x in observations),
              sum(x.get("kind") in {"credential", "crypto_key"} for x in observations)]
    for column, title, value in zip(st.columns(3), ("Recorded events", "Observed addresses", "Key / token observations"), counts):
        column.metric(t(title), value)
    with st.expander(t("Capture coverage and diagnostics"), expanded=bool(capture.get("errors")) or status != "completed"):
        coverage = capture.get("coverage")
        if isinstance(coverage, Mapping) and coverage:
            profile = str(coverage.get("profile") or "")
            columns = st.columns(3)
            columns[0].metric(t("Capture profile"), t(PROFILES[profile]) if profile in PROFILES else
                              _plain(profile) if profile else t("Not recorded"))
            for column, field, title in zip(columns[1:], ("observed_seconds", "requested_seconds"),
                                             ("Observed duration (seconds)", "Requested duration (seconds)")):
                value = coverage.get(field)
                valid = (type(value) is int or type(value) is float and math.isfinite(value)) and value >= 0
                shown = (str(value) if type(value) is int else f"{value:g}") if valid else t("Not recorded")
                column.metric(t(title), shown)
            st.caption(t("Observed duration is recording time, not a measure of screen or code coverage."))
            if coverage.get("ui_exploration") is False:
                st.caption(t("No automated screen exploration was recorded for this session."))
        else:
            st.caption(t("Capture timing and profile metadata were not recorded."))
        options = capture.get("options")
        if isinstance(options, Mapping) and type(options.get("native_hooks")) is bool:
            requested_mode = t("Java and native observation requested") if options["native_hooks"] else t("Java-only observation requested")
            st.text(f"{t('Requested hook mode')}: {requested_mode}")
            if not options["native_hooks"]:
                st.warning(t("Native DNS, socket and TLS observation was disabled for this capture."))
        capabilities = _records(capture.get("capabilities"))
        if capabilities:
            st.dataframe(pd.DataFrame([{t("Capability"): _plain(x.get("name") or x.get("hook")),
                                        t("Status"): (_plain(x.get("status")) if x.get("status") else
                                            t("Hook available") if x.get("available") is True else
                                            t("Hook unavailable") if x.get("available") is False else ""),
                                        t("Details"): _plain(x.get("details") or x.get("detail") or x.get("error") or x.get("reason"))}
                                       for x in capabilities]), hide_index=True, width="stretch")
        else:
            st.caption(t("No hook coverage metadata was recorded."))
        for limitation in capture.get("limitations") or []:
            st.warning(_plain(t(str(limitation))))
        for error in capture.get("errors") or []:
            st.error(_plain(error))

    if not observations:
        st.info(t("No runtime values were recorded in this session. This is not evidence that "
                  "the app has no network traffic or security issues."))
    else:
        query = st.text_input(t("Search runtime values, APIs or locations"), key=prefix + "_query").casefold().strip()
        kind_names = {"all": t("All observation types"), **{key: t(value) for key, value in KINDS.items()}}
        kind = st.selectbox(t("Observation type"), list(kind_names), format_func=kind_names.get,
                            key=prefix + "_kind")
        indices = [i for i, item in enumerate(observations)
                   if (kind == "all" or item.get("kind") == kind)
                   and (not query or query in json.dumps(item, ensure_ascii=False).casefold())]
        st.caption(t("Showing %d of %d runtime observations.") % (len(indices), len(observations)))
        if not indices:
            st.info(t("No recorded values match these filters."))
        else:
            selected_key, grid_key = prefix + "_observation", prefix + "_grid"
            if st.session_state.get(selected_key) not in indices:
                st.session_state[selected_key] = indices[0]
            left, right = st.columns([1.15, 1], gap="medium")
            with left:
                rows = [{t("Type"): t(KINDS.get(str(observations[i].get("kind")), "Observed value")),
                         t("Full observed value"): _plain(observations[i].get("value")),
                         t("Observed API"): _plain(observations[i].get("api")),
                         t("Observed at"): _plain(observations[i].get("timestamp"))} for i in indices]
                st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", key=grid_key,
                             on_select=lambda: _pick_row(grid_key, selected_key, indices),
                             selection_mode="single-row")
                labels = {i: f"{i + 1} · {t(KINDS.get(str(observations[i].get('kind')), 'Observed value'))} · "
                             f"{_plain(observations[i].get('api') or observations[i].get('label'))}" for i in indices}
                selected = st.selectbox(t("Open recorded value"), indices, format_func=labels.get,
                                        key=selected_key)
            with right:
                _render_observation(result, capture, observations[selected], t,
                                    f"{prefix}_{selected}", on_open_source)
    st.download_button(t("Download runtime capture JSON"), json.dumps(capture, ensure_ascii=False, indent=2),
                       file_name="runtime-capture.json", mime="application/json", key=prefix + "_json")
    st.download_button(t("Download runtime events JSONL"),
                       "\n".join(json.dumps(event, ensure_ascii=False) for event in events),
                       file_name="runtime-events.jsonl", mime="application/x-ndjson", key=prefix + "_jsonl")


def render_dynamic(result: ScanResult | None, t: Text, *, environment: Mapping | None = None,
                   sessions: Sequence[Mapping] = (), on_run: Callable[[dict], Any] | None = None,
                   on_import: Callable[[bytes, str], Any] | None = None,
                   on_load: Callable[[int], Mapping | None] | None = None,
                   on_reconnect: Callable[[str], Mapping] | None = None,
                   on_open_source: Callable[[str, int], None] | None = None) -> None:
    """Render controls and supplied captures; callbacks handle all device/storage actions."""
    environment = environment or {}
    sessions = _records(sessions)
    prefix = "dynamic_" + str(getattr(result, "scan_id", None) or id(result))
    st.subheader(t("Dynamic analysis"))
    st.caption(t("Record actual values while the app runs. Observed traffic, keys and call stacks "
                 "are separate from static findings; unvisited screens and encrypted or unsupported "
                 "paths may remain unobserved."))
    package = str(result.app.get("package") or "") if result is not None else ""
    with st.expander(t("Runtime capture setup"), expanded=not sessions):
        if package:
            st.text(f"{t('Target package')}: {_plain(package)}")
        else:
            st.info(t("Select a scanned Android application before starting a runtime capture."))
        devices = _records(environment.get("devices"))
        labels = {str(d.get("serial")): " · ".join(_plain(x) for x in (
            d.get("name") or d.get("model") or d.get("serial"), d.get("serial"),
            d.get("state") or "unknown") if x) for d in devices if d.get("serial")}
        if labels and st.session_state.get(prefix + "_device") not in labels:
            st.session_state[prefix + "_device"] = next(iter(labels))
        device_column, reconnect_column = st.columns([3, 1]) if on_reconnect is not None else (st.container(), None)
        with device_column:
            serial = st.selectbox(t("Android device"), list(labels), format_func=labels.get,
                                  key=prefix + "_device", disabled=not labels) if labels else ""
        if reconnect_column is not None:
            with reconnect_column:
                if st.button(t("Reconnect lab observer"), key=prefix + "_reconnect",
                             disabled=not serial or bool(st.session_state.get(CAPTURE_ACTIVE))):
                    try:
                        reconnected = on_reconnect(serial)
                        if isinstance(reconnected, Mapping) and reconnected.get("success") is True:
                            st.session_state[prefix + "_reconnect_notice"] = True
                            st.rerun()
                        else:
                            st.error(t("The lab observer could not be reconnected."))
                            if isinstance(reconnected, Mapping):
                                detail = reconnected.get("error") or reconnected.get("errors") or reconnected.get("message") or reconnected.get("reason")
                                if detail:
                                    st.code(_plain(detail), language="text")
                    except Exception as exc:
                        st.error(t("The lab observer could not be reconnected."))
                        st.code(_plain(exc), language="text")
        if st.session_state.pop(prefix + "_reconnect_notice", False):
            st.success(t("Lab observer reconnected. Device status has been refreshed."))
        if not labels:
            st.warning(t("No Android device is available for capture."))
        device = next((d for d in devices if d.get("serial") == serial), {})
        duration = st.number_input(t("Capture duration (seconds)"), min_value=10, max_value=300,
                                   value=30, step=5, key=prefix + "_duration")
        modes = {"spawn": t("Install and restart the application"), "attach": t("Attach to the running application")}
        mode = st.selectbox(t("Capture mode"), list(modes), format_func=modes.get, key=prefix + "_mode")
        native_hooks = st.checkbox(t("Observe native DNS and TLS calls"), value=True, key=prefix + "_native_hooks",
            help=t("Disable to compare Java hooks alone when native compatibility issues occur. "
                   "This reduces visibility into native DNS, socket and TLS calls."))
        st.caption(t("During capture, use the selected Android device to open the screens you want "
                     "to inspect. Only the selected process and executed actions are observed."))
        reasons = list(environment.get("reasons") or [])
        ready = bool(environment.get("available")) and bool(package and serial and on_run) and not st.session_state.get(CAPTURE_ACTIVE)
        if device.get("state") not in {"device", "online", "connected"}:
            ready = False
            if serial:
                reasons.append(t("The selected Android device is not connected or authorized."))
        for reason in dict.fromkeys(str(reason) for reason in reasons):
            st.warning(_plain(reason))
        if not environment.get("available") and not reasons:
            st.info(t("Runtime capture prerequisites are unavailable. Check device and instrumentation status."))
        if environment.get("capabilities"):
            with st.expander(t("Available capture tools")):
                st.json(environment["capabilities"])
        if st.button(t("Start runtime capture"), disabled=not ready, key=prefix + "_run", type="primary"):
            try:
                st.session_state[CAPTURE_ACTIVE] = True
                captured = on_run({"package": package, "serial": serial, "duration_seconds": int(duration),
                                   "spawn": mode == "spawn", "native_hooks": native_hooks})
                if isinstance(captured, Mapping):
                    sessions = [captured, *sessions]
                    st.session_state[prefix + "_session"] = 0
            except Exception as exc:
                st.error(t("Runtime capture could not finish."))
                st.code(_plain(exc), language="text")
            finally:
                st.session_state[CAPTURE_ACTIVE] = False
        if st.button(t("Refresh devices"), key=prefix + "_refresh"):
            st.rerun()
    if on_import is not None:
        with st.expander(t("Import an existing runtime capture")):
            st.caption(t("Import a capture JSON exported by this analyzer. Imported evidence remains "
                         "labelled separately from a capture witnessed by this dashboard."))
            uploaded = st.file_uploader(t("Runtime capture JSON"), type=["json"], key=prefix + "_upload")
            if st.button(t("Import capture"), disabled=uploaded is None, key=prefix + "_import"):
                if uploaded.size > MAX_IMPORT_BYTES:
                    st.error(t("The runtime capture exceeds the 64 MiB import limit."))
                else:
                    try:
                        imported = on_import(uploaded.getvalue(), uploaded.name)
                        if isinstance(imported, Mapping):
                            sessions = [imported, *sessions]
                            st.session_state[prefix + "_session"] = 0
                    except Exception as exc:
                        st.error(t("The runtime capture could not be imported."))
                        st.code(_plain(exc), language="text")
    if not sessions:
        st.info(t("No runtime capture has been recorded for this scan yet."))
        return
    labels = {i: f"{_plain(c.get('started_at'))} · {_plain(c.get('serial'))} · "
                 f"{t(STATUS.get(str(c.get('status')), 'Capture status unavailable'))}"
              for i, c in enumerate(sessions)}
    if st.session_state.get(prefix + "_session") not in labels:
        st.session_state[prefix + "_session"] = 0
    selected = st.selectbox(t("Recorded capture session"), list(labels), format_func=labels.get,
                            key=prefix + "_session")
    capture = sessions[selected]
    if "events" not in capture or "observations" not in capture:
        try:
            loaded = on_load(capture["capture_id"]) if on_load is not None and capture.get("capture_id") else None
        except Exception as exc:
            st.error(t("The archived runtime capture could not be loaded."))
            st.code(_plain(exc), language="text")
            return
        if not isinstance(loaded, Mapping) or "events" not in loaded or "observations" not in loaded:
            st.warning(t("The archived runtime evidence is unavailable. Its summary is not a complete capture."))
            return
        capture = loaded
    session_key = str(capture.get("capture_id") or capture.get("session_id") or selected)
    _render_capture(result, capture, t, prefix + "_" + session_key, on_open_source)
