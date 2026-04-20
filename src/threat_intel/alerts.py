import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")

HIGH_CONFIDENCE_THRESHOLD = 75


def should_alert(ioc: dict) -> bool:
    return ioc.get("risk_score", 0) >= HIGH_CONFIDENCE_THRESHOLD


def send_slack(iocs: list[dict], stats: dict) -> bool:
    if not SLACK_WEBHOOK_URL:
        return False

    high = [i for i in iocs if should_alert(i)]
    if not high:
        return False

    lines = "\n".join(
        f"• `{i['value']}` ({i['type']}) — risk {i['risk_score']}/100 — {', '.join(i['sources'])}"
        for i in high[:10]
    )

    payload = {
        "text": f":rotating_light: *Threat Intel Alert* — {len(high)} high-confidence IOCs detected",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":rotating_light: *Threat Intel Alert*\n"
                        f"*{len(high)} high-confidence IOCs* (score >= {HIGH_CONFIDENCE_THRESHOLD})\n"
                        f"Total IOCs analyzed: {stats['total_iocs']} | "
                        f"Cross-source matches: {stats['cross_source_matches']}"
                    ),
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top indicators:*\n{lines}"},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Generated at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                    }
                ],
            },
        ],
    }

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        print(f"Slack alert failed: {e}")
        return False


def send_email(iocs: list[dict], stats: dict) -> bool:
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASSWORD, ALERT_EMAIL_TO]):
        return False

    high = [i for i in iocs if should_alert(i)]
    if not high:
        return False

    rows = "\n".join(
        f"  - {i['value']} ({i['type']}) | Risk: {i['risk_score']}/100 | Sources: {', '.join(i['sources'])}"
        for i in high[:20]
    )

    body = f"""Threat Intelligence Alert
Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

{len(high)} high-confidence IOCs detected (score >= {HIGH_CONFIDENCE_THRESHOLD})
Total IOCs analyzed: {stats['total_iocs']}
Cross-source matches: {stats['cross_source_matches']}

Top indicators:
{rows}
"""

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_EMAIL_TO
    msg["Subject"] = f"[Threat Intel] {len(high)} high-confidence IOCs detected"
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, ALERT_EMAIL_TO, msg.as_string())
        return True
    except Exception as e:
        print(f"Email alert failed: {e}")
        return False


def dispatch(iocs: list[dict], stats: dict) -> dict:
    return {
        "slack": send_slack(iocs, stats),
        "email": send_email(iocs, stats),
    }