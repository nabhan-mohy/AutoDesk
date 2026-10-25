# Windows 11 manual verification checklist (issue #4)

GitHub-hosted `windows-latest` runners cover the unit-test matrix (PowerShell
and CIM cmdlets exist there), but they have **no printers installed** and
block some network probes, so the checks below must be performed once per
release on a real dealership-style Windows 11 PC. Track completion here or in
the PR description.

## Setup
- [ ] Python 3.12+ installed (`python --version`)
- [ ] `python -m pip install -r requirements.txt` completes without errors
- [ ] `python -m pytest -q` -> all tests pass

## Dashboard
- [ ] `python -m streamlit run app.py` opens http://localhost:8501
- [ ] Title, version and readiness banner render correctly
- [ ] **Run Full Health Check** completes with live progress and elapsed time
- [ ] Individual category buttons (System / Network / Printer) each work
- [ ] One deliberately broken config entry (e.g. unreachable service host)
      produces a useful FAIL/WARNING row — the app does not crash

## Windows-specific diagnostics
- [ ] Printers listed via PowerShell CIM (`Get-CimInstance Win32_Printer`) match
      Settings > Printers & scanners; default printer identified correctly
- [ ] Print Spooler state matches `services.msc`
- [ ] Queue job counts match what Windows shows (where permissions allow)
- [ ] Configured network printer IPs produce PASS/WARNING rows as expected
- [ ] Gateway/DNS/internet rows classify sensibly on the shop LAN
      (ICMP-blocked router => WARNING, not a false NOT READY)

## Reports
- [ ] CSV opens in Excel: columns Timestamp/Category/Check/Status/Observed/
      Expected/Recommendation present; hostname + version in header/metadata
- [ ] JSON parses (e.g. `python -m json.tool < report.json`)
- [ ] HTML renders in a browser with the summary table
- [ ] All three download buttons save files locally; no credentials/tokens
      appear in any report file
