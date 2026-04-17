"""
Alert Service — Email, Slack, MS Teams notifications
"""
import logging
import httpx
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.orm import Session

from models import Advisory, User, AlertLog
from config import settings

logger = logging.getLogger("alerts")


def _build_email_html(advisory: Advisory) -> str:
    severity_color = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#16a34a",
        "informational": "#2563eb",
    }.get(advisory.severity.value, "#6b7280")

    cves = ", ".join(advisory.cve_ids or []) or "N/A"
    sector = advisory.sector.name if advisory.sector else "General"

    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#0f172a;color:#f1f5f9;padding:20px;">
    <div style="max-width:600px;margin:auto;background:#1e293b;border-radius:8px;overflow:hidden;">
      <div style="background:{severity_color};padding:16px 24px;">
        <h1 style="margin:0;font-size:18px;color:#fff;">
          🔴 SecureEye CRITICAL ALERT — {advisory.severity.value.upper()}
        </h1>
      </div>
      <div style="padding:24px;">
        <h2 style="color:#f1f5f9;margin-top:0;">{advisory.title}</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:6px 0;color:#94a3b8;width:120px;">CVE IDs</td>
              <td style="padding:6px 0;color:#f1f5f9;font-weight:bold;">{cves}</td></tr>
          <tr><td style="padding:6px 0;color:#94a3b8;">CVSS Score</td>
              <td style="padding:6px 0;color:{severity_color};font-weight:bold;">
                {advisory.cvss_score or "N/A"}</td></tr>
          <tr><td style="padding:6px 0;color:#94a3b8;">Sector</td>
              <td style="padding:6px 0;color:#f1f5f9;">{sector}</td></tr>
          <tr><td style="padding:6px 0;color:#94a3b8;">KEV</td>
              <td style="padding:6px 0;color:#f1f5f9;">
                {'✅ Yes — CISA Known Exploited' if advisory.is_kev else 'No'}</td></tr>
        </table>
        <hr style="border-color:#334155;margin:16px 0;">
        <h3 style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px;">
          Description</h3>
        <p style="color:#cbd5e1;line-height:1.6;">{advisory.description or ''}</p>
        {'<h3 style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px;">Mitigation</h3><p style="color:#cbd5e1;line-height:1.6;">' + (advisory.mitigation or '') + '</p>' if advisory.mitigation else ''}
        <div style="margin-top:24px;padding:16px;background:#0f172a;border-radius:6px;
                    border-left:4px solid {severity_color};">
          <p style="margin:0;color:#94a3b8;font-size:12px;">
            SecureEye | Wipro Threat Intelligence Team<br>
            This is an automated alert. Do not reply to this email.
          </p>
        </div>
      </div>
    </div>
    </body></html>
    """


async def send_email_alert(advisory: Advisory, recipients: list[str], db: Session):
    if not settings.SMTP_USER or not recipients:
        logger.warning("Email alert skipped — SMTP not configured or no recipients")
        return

    log = AlertLog(
        advisory_id=advisory.id,
        channel="email",
        recipients=recipients,
        status="pending"
    )
    db.add(log)
    db.commit()

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SecureEye ALERT] {advisory.severity.value.upper()}: {advisory.title[:60]}"
        msg["From"] = settings.ALERT_FROM_EMAIL
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(_build_email_html(advisory), "html"))

        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            use_tls=False,
            start_tls=True,
        )
        log.status = "sent"
        db.commit()
        logger.info(f"Email alert sent for advisory {advisory.id} to {len(recipients)} recipients")
    except Exception as e:
        log.status = "failed"
        log.error_msg = str(e)
        db.commit()
        logger.error(f"Email alert failed for advisory {advisory.id}: {e}")


async def send_slack_alert(advisory: Advisory, db: Session):
    if not settings.SLACK_WEBHOOK_URL:
        logger.info("Slack alert skipped — webhook not configured")
        return

    severity_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}.get(
        advisory.severity.value, "🔵"
    )
    cves = ", ".join(advisory.cve_ids or []) or "N/A"
    log = AlertLog(advisory_id=advisory.id, channel="slack", recipients=[], status="pending")
    db.add(log)
    db.commit()

    payload = {
        "text": f"{severity_emoji} *SecureEye Critical Alert*",
        "attachments": [{
            "color": "#dc2626" if advisory.severity.value == "critical" else "#ea580c",
            "fields": [
                {"title": "Advisory", "value": advisory.title, "short": False},
                {"title": "Severity", "value": advisory.severity.value.upper(), "short": True},
                {"title": "CVSS Score", "value": str(advisory.cvss_score or "N/A"), "short": True},
                {"title": "CVE IDs", "value": cves, "short": True},
                {"title": "KEV", "value": "Yes ⚠️" if advisory.is_kev else "No", "short": True},
            ],
            "footer": "SecureEye | Wipro Threat Intelligence",
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
            r.raise_for_status()
        log.status = "sent"
        db.commit()
        logger.info(f"Slack alert sent for advisory {advisory.id}")
    except Exception as e:
        log.status = "failed"
        log.error_msg = str(e)
        db.commit()
        logger.error(f"Slack alert failed: {e}")


async def send_teams_alert(advisory: Advisory, db: Session):
    if not settings.TEAMS_WEBHOOK_URL:
        return

    cves = ", ".join(advisory.cve_ids or []) or "N/A"
    log = AlertLog(advisory_id=advisory.id, channel="teams", recipients=[], status="pending")
    db.add(log)
    db.commit()

    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "dc2626",
        "summary": f"SecureEye Alert: {advisory.title}",
        "sections": [{
            "activityTitle": f"🚨 SecureEye Critical Alert",
            "activitySubtitle": advisory.title,
            "facts": [
                {"name": "Severity", "value": advisory.severity.value.upper()},
                {"name": "CVSS Score", "value": str(advisory.cvss_score or "N/A")},
                {"name": "CVE IDs", "value": cves},
                {"name": "KEV", "value": "Yes" if advisory.is_kev else "No"},
            ]
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(settings.TEAMS_WEBHOOK_URL, json=card)
            r.raise_for_status()
        log.status = "sent"
        db.commit()
    except Exception as e:
        log.status = "failed"
        log.error_msg = str(e)
        db.commit()


async def send_ntfy_alert(advisory: Advisory):
    if not hasattr(settings, "NTFY_TOPIC") or not settings.NTFY_TOPIC:
        return

    severity_emoji = {"critical": "🚨", "high": "🔴", "medium": "🟠", "low": "🟡"}.get(
        advisory.severity.value, "🔵"
    )
    
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {
                "Title": f"SecureEye: {advisory.severity.value.upper()} Alert",
                "Priority": "5" if advisory.severity.value == "critical" else "3",
                "Tags": f"warning,{severity_emoji}"
            }
            content = f"{advisory.title}\nCVSS: {advisory.cvss_score or 'N/A'}"
            r = await client.post(
                f"https://ntfy.sh/{settings.NTFY_TOPIC}",
                content=content,
                headers=headers
            )
            r.raise_for_status()
            logger.info(f"NTFY alert sent for topic: {settings.NTFY_TOPIC}")
    except Exception as e:
        logger.error(f"NTFY alert failed: {e}")


async def trigger_critical_alerts(advisory: Advisory, db: Session):
    """Called when a critical advisory is published. Sends all configured alerts."""
    # Get subscribed users
    query = db.query(User).filter(User.is_active == True, User.alert_subscribed == True)
    all_users = query.all()
    critical_subscribers = [u for u in all_users if not u.alert_critical_only or advisory.is_critical_alert]
    emails = [u.email for u in critical_subscribers if u.email]

    await send_email_alert(advisory, emails, db)
    await send_slack_alert(advisory, db)
    await send_teams_alert(advisory, db)
    await send_ntfy_alert(advisory)
