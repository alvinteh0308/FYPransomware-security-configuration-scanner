# FYP Web Dashboard - Centralized Ransomware Misconfiguration Scanner

This version upgrades the original CLI scanner into a Flask web dashboard with manual scanning, scan history, saved targets, scheduled scanning, numeric risk scoring, dashboard charts, and PDF report export.

## Setup

```bash
cd fyp_web_dashboard
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
python app.py
```

Open the browser:

```text
http://127.0.0.1:5000
```

## Features

- Web dashboard for Linux and Windows target scanning
- Manual scan form
- Saved targets for scheduled scanning
- Configurable scheduled scan interval
- Numeric risk score: 0-100
- Risk level: Low, Medium, High
- Dashboard charts:
  - PASS / FAIL / INFO distribution
  - HIGH / MEDIUM / LOW risk distribution
  - Windows vs Linux average risk score
- PDF report export from each scan result page
- Scan history stored in `data/scan_results.json`
- Uses existing SSH and WinRM scanning logic from `scanner_core.py`

## Risk Score Formula

Each check is converted into risk points based on status and severity:

- PASS = 0 points
- FAIL + HIGH = 20 points
- FAIL + MEDIUM = 12 points
- FAIL + LOW = 5 points
- INFO + HIGH = 12 points
- INFO + MEDIUM = 7 points
- INFO + LOW = 2 points

Final score:

```text
Risk Score = Total Risk Points / Maximum Possible Points x 100
```

Risk level:

```text
0-39 = Low
40-69 = Medium
70-100 = High
```

## Important FYP Note

For demo/lab use, saved target credentials are stored locally in JSON so scheduled scanning can run. In the final report, mention this as a limitation and recommend encrypted credential storage for future improvement.
