"""Automated genuine screenshot capture tool for LogAnalyzer Pro."""

import subprocess
import time
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import urllib.request
from loganalyzer.config import REPORTS_DIR

CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SCREENSHOTS_DIR = BASE_DIR / "assets" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


def capture():
    # Verify Chrome exists
    if not Path(CHROME_PATH).exists():
        print(f"Chrome not found at {CHROME_PATH}")
        return False

    port = 8502
    cmd = [
        sys.executable, "-m", "streamlit", "run", "app.py",
        "--server.port", str(port),
        "--server.headless", "true",
        "--browser.gatherUsageStats", "false"
    ]

    print("Starting Streamlit process...")
    proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        # Wait for Streamlit to start
        health_url = f"http://localhost:{port}/_stcore/health"
        healthy = False
        for attempt in range(25):
            time.sleep(1)
            try:
                with urllib.request.urlopen(health_url, timeout=2) as resp:
                    if resp.status == 200:
                        healthy = True
                        break
            except Exception:
                continue

        if not healthy:
            print("Streamlit failed to become healthy in time.")
            out, err = proc.communicate(timeout=5)
            print("Streamlit stdout:", out.decode('utf-8', errors='ignore'))
            print("Streamlit stderr:", err.decode('utf-8', errors='ignore'))
            return False

        print("Streamlit is live. Capturing genuine page screenshots...")
        time.sleep(3)  # Allow charts to render

        pages = [
            ("overview", SCREENSHOTS_DIR / "01_soc_overview.png"),
            ("ingestion", SCREENSHOTS_DIR / "02_log_ingestion.png"),
            ("incidents", SCREENSHOTS_DIR / "03_incident_investigation.png"),
            ("ip_intel", SCREENSHOTS_DIR / "04_ip_intelligence.png"),
            ("mitre", SCREENSHOTS_DIR / "05_mitre_attack_view.png"),
            ("reports", SCREENSHOTS_DIR / "06_reports_and_exports.png"),
        ]

        for p_name, out_path in pages:
            url = f"http://localhost:{port}/?page={p_name}"
            chrome_cmd = [
                CHROME_PATH,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--window-size=1440,920",
                f"--screenshot={str(out_path)}",
                url
            ]
            print(f"Capturing {p_name} -> {out_path.name}")
            subprocess.run(chrome_cmd, timeout=30)
            time.sleep(2)

        # Also capture PDF report rendering
        pdf_file = REPORTS_DIR / "Sample_SOC_Report.pdf"
        if pdf_file.exists():
            pdf_out = SCREENSHOTS_DIR / "07_pdf_investigation_report.png"
            chrome_pdf_cmd = [
                CHROME_PATH,
                "--headless=new",
                "--disable-gpu",
                "--no-sandbox",
                "--window-size=1200,900",
                f"--screenshot={str(pdf_out)}",
                f"file:///{str(pdf_file).replace('\\', '/')}"
            ]
            print(f"Capturing PDF report -> {pdf_out.name}")
            subprocess.run(chrome_pdf_cmd, timeout=30)

        print("All genuine screenshots captured successfully!")
        return True

    finally:
        print("Stopping Streamlit process...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    success = capture()
    if not success:
        sys.exit(1)
