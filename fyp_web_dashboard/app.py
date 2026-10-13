import json
import threading
import time
from datetime import datetime
from io import BytesIO
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from scanner_core import generate_html_report, scan_linux, scan_windows

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
RESULTS_FILE = DATA_DIR / "scan_results.json"
TARGETS_FILE = DATA_DIR / "saved_targets.json"

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-demo"

scheduler_state = {
    "enabled": False,
    "interval_minutes": 60,
    "last_run": None,
    "next_run": None,
    "status": "Stopped"
}


# =========================================================
# STORAGE HELPERS
# =========================================================

def load_json(path, default):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    DATA_DIR.mkdir(exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =========================================================
# RISK SCORING ENGINE
# =========================================================

def result_risk_points(result):
    """
    Converts each check result into numeric risk points.
    This makes the dashboard more measurable for FYP evaluation.
    """
    status = result.get("status", "INFO").upper()
    risk = result.get("risk", "LOW").upper()

    if status == "PASS":
        return 0

    if risk == "HIGH":
        return 20 if status == "FAIL" else 12
    if risk == "MEDIUM":
        return 12 if status == "FAIL" else 7
    if risk == "LOW":
        return 5 if status == "FAIL" else 2
    return 5


def calculate_risk_score(results):
    """
    Produces a normalized 0-100 risk score.
    0 means no detected configuration risk, 100 means all checks are high-risk failures.
    """
    if not results:
        return 0, "Unknown"

    max_possible = len(results) * 20
    raw_score = sum(result_risk_points(r) for r in results)
    score = round((raw_score / max_possible) * 100)
    score = max(0, min(score, 100))

    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"
    return score, level


def summarize(results):
    score, level = calculate_risk_score(results)
    return {
        "total": len(results),
        "pass": sum(1 for r in results if r.get("status") == "PASS"),
        "fail": sum(1 for r in results if r.get("status") == "FAIL"),
        "info": sum(1 for r in results if r.get("status") == "INFO"),
        "high": sum(1 for r in results if r.get("risk") == "HIGH"),
        "medium": sum(1 for r in results if r.get("risk") == "MEDIUM"),
        "low": sum(1 for r in results if r.get("risk") == "LOW"),
        "risk_score": score,
        "risk_level": level,
    }




def ensure_summary_fields(records):
    """Adds risk_score and risk_level to older scan records if they were created before this upgrade."""
    changed = False
    for record in records:
        summary = record.get("summary", {})
        if "risk_score" not in summary or "risk_level" not in summary:
            record["summary"] = summarize(record.get("results", []))
            changed = True
    if changed:
        save_json(RESULTS_FILE, records[:100])
    return records

def build_dashboard_metrics(records):
    latest = records[0] if records else None
    status_chart = {
        "PASS": latest["summary"].get("pass", 0) if latest else 0,
        "FAIL": latest["summary"].get("fail", 0) if latest else 0,
        "INFO": latest["summary"].get("info", 0) if latest else 0,
    }
    risk_chart = {
        "HIGH": latest["summary"].get("high", 0) if latest else 0,
        "MEDIUM": latest["summary"].get("medium", 0) if latest else 0,
        "LOW": latest["summary"].get("low", 0) if latest else 0,
    }

    os_metrics = {
        "Linux": {"count": 0, "score_total": 0},
        "Windows": {"count": 0, "score_total": 0},
    }
    for record in records:
        os_name = "Windows" if record.get("os_type", "").lower() == "windows" else "Linux"
        os_metrics[os_name]["count"] += 1
        os_metrics[os_name]["score_total"] += record.get("summary", {}).get("risk_score", 0)

    for item in os_metrics.values():
        item["avg_score"] = round(item["score_total"] / item["count"]) if item["count"] else 0

    return status_chart, risk_chart, os_metrics


# =========================================================
# PDF REPORT EXPORT
# =========================================================

def safe_text(value):
    if value is None:
        return ""
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.replace("\n", "<br/>")


def generate_pdf_report(record):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleCenter",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        spaceAfter=8,
    )
    normal = styles["BodyText"]
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7, leading=9)

    summary = record["summary"]
    story = [
        Paragraph("Centralized Ransomware Misconfiguration Scanner Report", title_style),
        Paragraph(f"Target: {safe_text(record['target_ip'])} | OS: {safe_text(record['os_type'])} | Source: {safe_text(record['source'])}", normal),
        Paragraph(f"Scan Time: {safe_text(record['timestamp'])}", normal),
        Spacer(1, 6),
    ]

    summary_data = [
        ["Risk Score", "Risk Level", "Total Checks", "PASS", "FAIL", "INFO", "HIGH", "MEDIUM", "LOW"],
        [
            f"{summary.get('risk_score', 0)}/100",
            summary.get("risk_level", "Unknown"),
            summary.get("total", 0),
            summary.get("pass", 0),
            summary.get("fail", 0),
            summary.get("info", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
        ],
    ]
    summary_table = Table(summary_data, repeatRows=1)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f3f4f6")),
    ]))
    story.extend([summary_table, Spacer(1, 10)])

    data = [["Check", "Status", "Risk", "Details", "Remediation"]]
    for result in record["results"]:
        data.append([
            Paragraph(safe_text(result.get("check")), small),
            Paragraph(safe_text(result.get("status")), small),
            Paragraph(safe_text(result.get("risk")), small),
            Paragraph(safe_text(result.get("details")), small),
            Paragraph(safe_text(result.get("remediation")), small),
        ])

    result_table = Table(data, repeatRows=1, colWidths=[42 * mm, 22 * mm, 22 * mm, 95 * mm, 84 * mm])
    result_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d1d5db")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
    ]))
    story.append(result_table)

    doc.build(story)
    buffer.seek(0)
    return buffer


# =========================================================
# SCAN EXECUTION
# =========================================================

def save_scan_record(target, results, source="Manual"):
    records = load_json(RESULTS_FILE, [])
    record = {
        "id": datetime.now().strftime("%Y%m%d%H%M%S%f"),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "target_ip": target["ip"],
        "os_type": target["os_type"],
        "summary": summarize(results),
        "results": results,
    }
    records.insert(0, record)
    save_json(RESULTS_FILE, records[:100])
    return record


def run_scan_for_target(target, source="Manual"):
    os_type = target["os_type"].lower()
    if os_type == "linux":
        results = scan_linux(target["ip"], target["username"], target["password"])
    elif os_type == "windows":
        results = scan_windows(target["ip"], target["username"], target["password"])
    else:
        raise ValueError("Invalid OS type")

    try:
        generate_html_report(results)
    except Exception:
        pass

    return save_scan_record(target, results, source=source)


def scheduler_loop():
    while True:
        if scheduler_state["enabled"]:
            scheduler_state["status"] = "Running"
            saved_targets = load_json(TARGETS_FILE, [])
            for target in saved_targets:
                try:
                    run_scan_for_target(target, source="Scheduled")
                except Exception as e:
                    error_result = [{
                        "target_ip": target.get("ip", "Unknown"),
                        "os": target.get("os_type", "Unknown"),
                        "check": "Scheduled Scan Error",
                        "status": "INFO",
                        "risk": "MEDIUM",
                        "details": str(e),
                        "remediation": "Verify target IP, credentials, network connectivity, SSH/WinRM service, and firewall rules."
                    }]
                    save_scan_record(target, error_result, source="Scheduled")

            scheduler_state["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            interval_seconds = max(1, int(scheduler_state["interval_minutes"])) * 60
            scheduler_state["next_run"] = datetime.fromtimestamp(time.time() + interval_seconds).strftime("%Y-%m-%d %H:%M:%S")
            time.sleep(interval_seconds)
        else:
            scheduler_state["status"] = "Stopped"
            time.sleep(2)


# =========================================================
# ROUTES
# =========================================================

@app.route("/")
def dashboard():
    records = ensure_summary_fields(load_json(RESULTS_FILE, []))
    saved_targets = load_json(TARGETS_FILE, [])
    latest = records[0] if records else None
    status_chart, risk_chart, os_metrics = build_dashboard_metrics(records)
    return render_template(
        "dashboard.html",
        records=records[:10],
        latest=latest,
        targets=saved_targets,
        scheduler=scheduler_state,
        status_chart=status_chart,
        risk_chart=risk_chart,
        os_metrics=os_metrics,
    )


@app.route("/scan", methods=["POST"])
def scan():
    target = {
        "os_type": request.form.get("os_type", "linux"),
        "ip": request.form.get("ip", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", "")
    }
    save_target = request.form.get("save_target") == "on"

    if not target["ip"] or not target["username"] or not target["password"]:
        flash("Please fill in IP address, username, and password.", "error")
        return redirect(url_for("dashboard"))

    try:
        record = run_scan_for_target(target, source="Manual")
        if save_target:
            targets = load_json(TARGETS_FILE, [])
            targets = [t for t in targets if not (t["ip"] == target["ip"] and t["os_type"] == target["os_type"])]
            targets.append(target)
            save_json(TARGETS_FILE, targets)
        flash("Scan completed successfully.", "success")
        return redirect(url_for("view_result", record_id=record["id"]))
    except Exception as e:
        flash(f"Scan failed: {e}", "error")
        return redirect(url_for("dashboard"))


@app.route("/result/<record_id>")
def view_result(record_id):
    records = ensure_summary_fields(load_json(RESULTS_FILE, []))
    record = next((r for r in records if r["id"] == record_id), None)
    if not record:
        flash("Result not found.", "error")
        return redirect(url_for("dashboard"))
    return render_template("result.html", record=record)


@app.route("/result/<record_id>/pdf")
def export_pdf(record_id):
    records = ensure_summary_fields(load_json(RESULTS_FILE, []))
    record = next((r for r in records if r["id"] == record_id), None)
    if not record:
        flash("Result not found.", "error")
        return redirect(url_for("dashboard"))

    pdf_buffer = generate_pdf_report(record)
    filename = f"scan_report_{record['target_ip']}_{record['id']}.pdf".replace(":", "-")
    return send_file(pdf_buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


@app.route("/scheduler", methods=["POST"])
def scheduler():
    action = request.form.get("action")
    interval = request.form.get("interval_minutes", "60")
    try:
        scheduler_state["interval_minutes"] = max(1, int(interval))
    except ValueError:
        scheduler_state["interval_minutes"] = 60

    if action == "start":
        scheduler_state["enabled"] = True
        scheduler_state["next_run"] = "Starting soon"
        flash("Scheduled scanning started.", "success")
    elif action == "stop":
        scheduler_state["enabled"] = False
        scheduler_state["next_run"] = None
        flash("Scheduled scanning stopped.", "success")
    return redirect(url_for("dashboard"))


@app.route("/targets/delete/<ip>/<os_type>", methods=["POST"])
def delete_target(ip, os_type):
    targets = load_json(TARGETS_FILE, [])
    targets = [t for t in targets if not (t["ip"] == ip and t["os_type"] == os_type)]
    save_json(TARGETS_FILE, targets)
    flash("Saved target removed.", "success")
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
