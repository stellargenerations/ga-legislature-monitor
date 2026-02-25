"""
GA Legislature Motor Vehicle Meeting Monitor
Continuously polls the GA House schedule API and sends a Telegram alert
when a Motor Vehicles committee meeting appears on the calendar.
"""

import hashlib
import time
import json
import os
import logging
import urllib.request
import urllib.parse
from datetime import datetime, timedelta, timezone

# --- Config (set via Railway environment variables) ---
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))  # seconds
KEYWORDS = ["interstate cooperation"]  # TEMP TEST - change back to ["motor vehicle", "motor vehicles"]

# --- GA Legislature API auth constants (from their public JS bundle) ---
OBSCURE_KEY = "jVEXFFwSu36BwwcP83xYgxLAhLYmKk"
KEY_PREFIX = "QFpCwKfd7f"
KEY_SUFFIX = "letvarconst"
API_BASE = "https://www.legis.ga.gov/api"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Auth ──────────────────────────────────────────────────────────────────────

def get_token() -> str:
    """Compute HMAC-style token from embedded JS constants and fetch a JWT."""
    ms = int(time.time() * 1000)
    raw = KEY_PREFIX + OBSCURE_KEY + KEY_SUFFIX + str(ms)
    key = hashlib.sha512(raw.encode()).hexdigest()
    url = f"{API_BASE}/authentication/token?key={key}&ms={ms}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode()).strip('"')


# ── API ───────────────────────────────────────────────────────────────────────

def fetch_meetings(token: str) -> list:
    """Fetch the next 14 days of House meetings from the GA Legislature API."""
    now = datetime.now(timezone.utc).astimezone()
    end = now + timedelta(days=14)

    # API expects JS toDateString() format e.g. "Wed Feb 25 2026"
    def fmt(dt):
        return dt.strftime("%a %b %d %Y")

    params = urllib.parse.urlencode({
        "chamber": 1,
        "startDate": fmt(now),
        "endDate": fmt(end),
    })
    url = f"{API_BASE}/meetings?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


# ── Alert ─────────────────────────────────────────────────────────────────────

def send_telegram(message: str):
    """Send a message via Telegram bot."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        log.warning("Telegram credentials not set — skipping alert")
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = json.dumps({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        resp = json.loads(r.read().decode())
        if not resp.get("ok"):
            log.error(f"Telegram send failed: {resp}")


# ── Motor Vehicle Detection ───────────────────────────────────────────────────

def is_motor_vehicle_meeting(meeting: dict) -> bool:
    subject = meeting.get("subject", "").lower()
    return any(kw in subject for kw in KEYWORDS)


def format_alert(meeting: dict) -> str:
    subject = meeting.get("subject", "Unknown")
    start = meeting.get("start", "")
    location = meeting.get("location", "Unknown location")
    agenda_url = meeting.get("agendaUri", "")
    livestream = meeting.get("livestreamUrl", "")

    # Parse the ISO datetime
    try:
        dt = datetime.fromisoformat(start)
        time_str = dt.strftime("%A, %B %d at %-I:%M %p")
    except Exception:
        time_str = start

    lines = [
        "🚨 <b>Motor Vehicle Meeting Detected!</b>",
        "",
        f"📋 <b>{subject}</b>",
        f"📅 {time_str}",
        f"📍 {location}",
    ]
    if agenda_url:
        lines.append(f"📄 <a href='{agenda_url}'>View Agenda</a>")
    if livestream:
        lines.append(f"📺 <a href='{livestream}'>Watch Livestream</a>")
    lines.append("")
    lines.append("🔗 <a href='https://www.legis.ga.gov/schedule/house'>Full House Schedule</a>")

    return "\n".join(lines)


# ── Main Loop ─────────────────────────────────────────────────────────────────

def main():
    log.info("GA Legislature Motor Vehicle Monitor starting...")
    log.info(f"Checking every {CHECK_INTERVAL} seconds | Keywords: {KEYWORDS}")

    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        log.error("TELEGRAM_TOKEN and TELEGRAM_CHAT_ID environment variables are required!")
        return

    # Track which meeting IDs we've already alerted on (avoid spam)
    alerted_ids: set = set()
    token = ""
    token_expires_at = 0

    # Send startup confirmation
    send_telegram("✅ <b>GA Legislature Monitor is running!</b>\nWatching for Motor Vehicles committee meetings on the House schedule.")
    log.info("Startup message sent to Telegram.")

    while True:
        try:
            # Refresh token every 4 minutes (it expires in ~5 min)
            if time.time() > token_expires_at:
                token = get_token()
                token_expires_at = time.time() + 240
                log.info("Auth token refreshed.")

            meetings = fetch_meetings(token)
            log.info(f"Fetched {len(meetings)} meetings.")

            new_alerts = 0
            for meeting in meetings:
                if not is_motor_vehicle_meeting(meeting):
                    continue

                meeting_id = meeting.get("id", meeting.get("start", ""))
                if meeting_id in alerted_ids:
                    continue  # Already alerted

                # New motor vehicle meeting found!
                log.info(f"MATCH: {meeting.get('subject')} on {meeting.get('start')}")
                alert_text = format_alert(meeting)
                send_telegram(alert_text)
                alerted_ids.add(meeting_id)
                new_alerts += 1

            if new_alerts == 0:
                log.info("No new motor vehicle meetings found.")

        except Exception as e:
            log.error(f"Error during check: {e}")
            # Don't crash the loop — try again next cycle

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
