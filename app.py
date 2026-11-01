
import csv
import io
from collections import Counter, defaultdict
from datetime import datetime
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

SAMPLE_LOGS = """timestamp,source_ip,event,username
2026-10-28 09:01:00,192.168.1.10,login_failed,admin
2026-10-28 09:01:05,192.168.1.10,login_failed,admin
2026-10-28 09:01:10,192.168.1.10,login_failed,admin
2026-10-28 09:01:15,192.168.1.10,login_failed,root
2026-10-28 09:02:00,10.0.0.8,login_success,neeraj
2026-10-28 09:03:00,192.168.1.25,file_access,admin
"""

def analyze_logs(raw):
    rows = list(csv.DictReader(io.StringIO(raw)))
    failed_by_ip = Counter()
    accounts_by_ip = defaultdict(set)
    events = []
    alerts = []

    for row in rows:
        timestamp = row.get("timestamp", "").strip()
        ip = row.get("source_ip", "unknown").strip()
        event = row.get("event", "").strip().lower()
        username = row.get("username", "unknown").strip()

        events.append({
            "timestamp": timestamp,
            "ip": ip,
            "event": event,
            "username": username
        })

        if event in {
            "login_failed", "failed_login", "authentication_failure"
        }:
            failed_by_ip[ip] += 1
            accounts_by_ip[ip].add(username)

    for ip, count in failed_by_ip.items():
        accounts = sorted(accounts_by_ip[ip])

        if count >= 3:
            alerts.append({
                "severity": "HIGH",
                "title": "Possible brute-force activity",
                "ip": ip,
                "evidence": (
                    f"{count} failed logins targeting "
                    f"{len(accounts)} account(s): {', '.join(accounts)}"
                ),
                "recommendation": (
                    "Review authentication logs, check for a subsequent "
                    "successful login, and consider rate limiting."
                )
            })

        if len(accounts) >= 3:
            alerts.append({
                "severity": "MEDIUM",
                "title": "Multiple accounts targeted",
                "ip": ip,
                "evidence": (
                    f"The same IP attempted logins for "
                    f"{len(accounts)} different accounts."
                ),
                "recommendation": (
                    "Review the affected accounts and inspect related "
                    "events from this IP."
                )
            })

    events.sort(key=lambda e: e["timestamp"])
    return rows, events, alerts

def render_page(raw, results=""):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberSentinel AI</title>
<style>
body {{ background:#101827; color:#e5e7eb; font-family:Arial;
padding:25px; max-width:1000px; margin:auto; }}
.card {{ background:#1c293b; padding:20px; border-radius:12px;
margin:18px 0; }}
textarea {{ width:100%; height:190px; background:#0b1220;
color:white; padding:12px; box-sizing:border-box; }}
button {{ background:#38bdf8; padding:12px 20px; border:0;
border-radius:7px; font-weight:bold; cursor:pointer; }}
.high {{ color:#fca5a5; }}
.medium {{ color:#fde68a; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ text-align:left; padding:9px; border-bottom:1px solid #374151; }}
</style>
</head>
<body>
<h1>🛡️ CyberSentinel AI</h1>
<p>Security log analysis and suspicious activity detection</p>
<div class="card">
<h2>Analyze security logs</h2>
<p>CSV columns: timestamp, source_ip, event, username</p>
<form method="post">
<textarea name="logs">{escape(raw)}</textarea><br><br>
<button type="submit">Analyze Logs</button>
</form>
</div>
{results}
<p><small>Alerts are heuristic indicators, not proof of an attack.
Only analyze logs you are authorized to access.</small></p>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_html(render_page(SAMPLE_LOGS))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length).decode("utf-8")
        raw = parse_qs(data).get("logs", [""])[0]

        try:
            rows, events, alerts = analyze_logs(raw)
            results = '<div class="card"><h2>Analysis Results</h2>'
            results += f"<p>Total log entries: {len(rows)}</p>"
            results += f"<p>Detected alerts: {len(alerts)}</p>"

            results += "<h3>Threat Alerts</h3>"
            if alerts:
                for alert in alerts:
                    css = alert["severity"].lower()
                    results += (
                        f'<h4 class="{css}">{escape(alert["severity"])}: '
                        f'{escape(alert["title"])}</h4>'
                        f'<p>Source IP: {escape(alert["ip"])}</p>'
                        f'<p>Evidence: {escape(alert["evidence"])}</p>'
                        f'<p>Recommended action: '
                        f'{escape(alert["recommendation"])}</p>'
                    )
            else:
                results += "<p>No configured detection rule was triggered.</p>"

            results += (
                "<h3>Event Timeline</h3>"
                "<table><tr><th>Timestamp</th><th>Source IP</th>"
                "<th>Event</th><th>Account</th></tr>"
            )
            for event in events:
                results += (
                    "<tr>"
                    f'<td>{escape(event["timestamp"])}</td>'
                    f'<td>{escape(event["ip"])}</td>'
                    f'<td>{escape(event["event"])}</td>'
                    f'<td>{escape(event["username"])}</td>'
                    "</tr>"
                )
            results += "</table></div>"
        except (csv.Error, UnicodeError, ValueError) as exc:
            results = (
                '<div class="card"><h2>Input error</h2><p>'
                + escape(str(exc)) + "</p></div>"
            )

        self.send_html(render_page(raw, results))

    def send_html(self, content):
        encoded = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        print(format % args)

if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), Handler)
    print("CyberSentinel AI running at http://127.0.0.1:8000")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("Server stopped.")
