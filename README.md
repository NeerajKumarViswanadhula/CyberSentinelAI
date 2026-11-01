# 🛡 CyberSentinel AI
### The AI That Reconstructs Cyberattacks

**CyberSentinel AI** is a cybersecurity threat detection and investigation dashboard designed to analyze security logs, identify suspicious activities, and help users understand potential cyberattacks.

## 🚀 Features

- **Security Log Analysis:** Analyze CSV-based security logs.
- **Threat Detection:** Identify repeated failed login attempts.
- **Suspicious IP Detection:** Highlight IP addresses associated with unusual login activity.
- **Attack Timeline:** Reconstruct events in chronological order.
- **Threat Classification:** Display security alerts based on suspicious activity.
- **Defensive Recommendations:** Suggest actions for investigating potential threats.
- **Hacker-Style Dashboard:** Interactive cybersecurity interface with a dark theme and neon-green visual design.

## 🛠 Technologies Used

- Python
- HTML5
- CSS3
- JavaScript
- CSV
- GitHub Pages

## 💻 How to Run

### Browser Version

1. Open the published GitHub Pages website.
2. Paste your security logs into the input area.
3. Click **EXECUTE THREAT SCAN**.
4. Review threat alerts, security statistics, and the attack timeline.

### Python Version

1. Install Python 3.12 or later.
2. Open the project folder in your terminal.
3. Run:

   `python app.py`

4. Open `http://127.0.0.1:8000` in your browser.

## 📄 CSV Log Format

Your input CSV should contain these columns:

`timestamp,source_ip,event,username`

Example:

```csv
timestamp,source_ip,event,username
2026-11-01 10:00:00,192.168.1.20,login_failed,admin
2026-11-01 10:00:05,192.168.1.20,login_failed,root
2026-11-01 10:00:10,192.168.1.20,login_failed,user1
2026-11-01 10:01:00,10.0.0.5,login_success,neeraj
```

## 🎯 Project Goal

To simplify cybersecurity investigation through automated security-log analysis, suspicious activity detection, attack timeline reconstruction, and intelligent security recommendations.

## 🔮 Future Enhancements

- Integration with NVIDIA open-source AI models.
- Nebius Token Factory AI integration.
- AI-powered threat explanations.
- Advanced attack pattern detection.
- Real-time security monitoring.

## ⚠️ Current Limitations

The GitHub Pages version performs rule-based analysis directly in the browser. It does not currently connect to a live AI model or monitor real-time network traffic.

## 📜 License

This project is licensed under the MIT License.

---

**Protect. Detect. Investigate.**

*CyberSentinel AI — Making Cybersecurity Investigation Smarter.*
