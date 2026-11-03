# Aegis SIEM — Security Analytics Workbench

A local-first Streamlit application for reviewing SIEM log exports from Excel. It provides column mapping, explainable heuristic detections, an interactive dashboard, event exploration, English/Spanish interface text, bilingual technical-report narratives, and PDF export.

## Start on Windows

1. Install **64-bit Python 3.10.x** from [python.org](https://www.python.org/downloads/release/python-31011/). The Windows Python Launcher (`py`) must be enabled. This package intentionally selects Python 3.10 even if other Python versions are installed.
2. Extract this ZIP to a folder you can write to.
3. Double-click `setup_windows.bat` once. It removes any old `.venv`, creates a clean Python 3.10 environment, and installs prebuilt binary packages only (so it will not attempt to compile Pandas).
4. Double-click `run_windows.bat` whenever you want to launch the app.
5. Your browser should open the local Streamlit address, normally `http://localhost:8501`.

## Start manually (Windows, macOS, or Linux)

```bash
py -3.10 -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
python -m pip install --only-binary=:all: -r requirements.txt
streamlit run app.py
```

## Windows setup troubleshooting

This Windows bundle explicitly uses 64-bit Python 3.10 (`py -3.10`) so the Python Launcher does not accidentally select a newer installation such as Python 3.15. It pins Pandas to 2.3.3 and installs binary wheels only. If setup says Python 3.10 is missing or not 64-bit, open Command Prompt and run `py -0p` to list installed interpreters. Confirm that a 64-bit Python 3.10 interpreter is listed. If dependency installation still fails, send the full error from the setup window; the installer intentionally stops rather than compiling Pandas.

## Workflow

1. Upload an `.xlsx` or `.xls` SIEM export.
2. Select the worksheet to analyze.
3. Confirm the suggested mapping. Available standard fields include timestamp, source/destination IP, username, event ID/name, severity, action/result, message, hostname, process, command line, outbound bytes, and country.
4. Adjust detection thresholds in the sidebar.
5. Run the analysis and use the single-page workspace navigation to switch between Command Center, Findings, Event Explorer, Reporting Center, and Data & Rules. Only the selected workspace page is rendered; navigation stays in the same browser tab.
6. Export filtered events or findings as CSV, or generate the technical PDF report.

The included `sample_logs.xlsx` is synthetic test data. It contains intentionally simulated authentication failures, a later successful login, a suspicious PowerShell command, a log-clearing signal, network fan-out, and large outbound transfer activity. Use it to explore the app before testing with real logs.

## Included detection logic

- Repeated authentication failures by source/account within a 10-minute window (or count-based fallback when timestamps are unavailable).
- Successful authentication after at least three recent failures within 30 minutes.
- Suspicious command-line patterns: encoded PowerShell, script/download cradles, selected living-off-the-land binaries, credential-dumping indicators, and shadow-copy deletion commands.
- Security/event log clearing indicators, including Windows Event ID 1102 patterns.
- Privileged access and privileged-group membership activity.
- High network destination fan-out, which may indicate scanning or discovery.
- Large outbound transfer threshold.
- Vendor-labeled High/Critical events not covered by a more specific local rule.

The PDF report contains findings, supporting event evidence, criticality, technical explanation, recommended action, and a prioritized action plan. The interface and generated finding narratives can be switched between English and Spanish. Original source-event text remains in its source language.

## Important security and accuracy notes

- The app is designed to process the workbook in the local Streamlit session. It does not send log content to an external analysis API and uses no remote font service. When deployed on a server, however, the server and its administrators can access uploaded data; do not upload sensitive production logs to an unapproved host.
- Detection rules are transparent triage heuristics, not proof of compromise. Validate findings against process trees, endpoint telemetry, identity logs, network records, threat intelligence, and change tickets.
- The risk score is a simple heuristic aggregation, not a calibrated probability or a compliance-grade risk measurement. It can saturate at 100 when multiple findings overlap.
- SIEM schemas differ. Automatic mapping is best-effort; confirm it manually. Numeric `bytes_out` values must be in bytes for the configured MB threshold to be interpreted correctly.
- Timestamps without timezone information are interpreted as UTC.
- This is a single-user MVP. It does not include authentication, role-based access control, persistent case storage, audit logging, multi-tenant isolation, or production deployment hardening.
- Use sanitized or synthetic data during demonstrations and development.



## Appearance customization

### Apply a visual update to an existing installation

If Aegis is already installed, you do **not** need to rerun `setup_windows.bat` for a visual-only update. Stop the running app with `Ctrl+C`, replace `app.py` and `.streamlit/config.toml` with the versions from this update, then launch `run_windows.bat` again. The Python dependencies are unchanged.


The sidebar includes appearance controls. Choose one of three palettes: **Graphite & Jade** (the default), **Midnight Blue**, or **Light Analyst**. Palette changes apply to the Streamlit theme tokens, interface surfaces, controls, text, data grids, and interactive charts.

The Typeface selector offers three distinct local font families: **Segoe UI · clean** (a modern sans-serif), **Georgia · editorial** (a traditional serif), and **Consolas · technical** (a monospaced typeface). These are common Windows fonts and do not require internet access or remote font downloads. The selected typeface is applied to interface text, controls, and Plotly charts.

Chart titles have a reserved top margin so they remain fully visible inside the responsive chart containers. These appearance settings do not change the colors or typography of the exported PDF report.


## SOC workspace navigation update

The current interface uses in-place workspace navigation rather than Streamlit tabs. Choose **Command Center**, **Findings**, **Event Explorer**, **Reporting Center**, or **Data & Rules** from the navigation row. Switching pages replaces the visible workspace content in the same browser tab; it does not open additional browser tabs.

The **Data & Rules** page owns workbook upload, worksheet selection, column mapping, and analysis execution. The uploaded workbook bytes and completed analysis are retained in the local Streamlit session when moving between workspace pages. Detection thresholds remain available in the sidebar.

To apply this update to an existing installation, stop Aegis with `Ctrl+C`, replace the existing `app.py` with the updated file, and run `run_windows.bat` again. No dependency installation is required.
