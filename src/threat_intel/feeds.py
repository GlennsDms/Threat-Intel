import os
import json
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

CACHE_DIR = Path("data/cache")
CACHE_TTL_HOURS = 6

OTX_BASE = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"


# ─── Cache ────────────────────────────────────────────────────────────────────

def _cache_path(key: str) -> Path:
    hashed = hashlib.md5(key.encode()).hexdigest()
    return CACHE_DIR / f"{hashed}.json"


def _cache_get(key: str) -> dict | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        cached_at = datetime.fromisoformat(data["_cached_at"])
        if cached_at.tzinfo is None:
            cached_at = cached_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - cached_at > timedelta(hours=CACHE_TTL_HOURS):
            return None
        return data["payload"]
    except Exception:
        return None


def _cache_set(key: str, payload: dict):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(key)
    path.write_text(json.dumps({
        "_cached_at": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }))


# ─── OTX ──────────────────────────────────────────────────────────────────────

def otx_get_pulse(pulse_id: str) -> dict:
    cache_key = f"otx_pulse_{pulse_id}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not OTX_API_KEY:
        raise ValueError("OTX_API_KEY not set in .env")

    response = requests.get(
        f"{OTX_BASE}/pulses/{pulse_id}",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        timeout=15,
    )
    response.raise_for_status()
    data = response.json()
    _cache_set(cache_key, data)
    return data


def otx_get_subscribed_pulses(limit: int = 10) -> list[dict]:
    cache_key = f"otx_subscribed_{limit}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not OTX_API_KEY:
        raise ValueError("OTX_API_KEY not set in .env")

    response = requests.get(
        f"{OTX_BASE}/pulses/subscribed",
        headers={"X-OTX-API-KEY": OTX_API_KEY},
        params={"limit": limit},
        timeout=15,
    )
    response.raise_for_status()
    results = response.json().get("results", [])
    _cache_set(cache_key, results)
    return results


def otx_lookup_ioc(ioc_type: str, ioc_value: str) -> dict:
    """
    ioc_type: IPv4, domain, hostname, url, FileHash-MD5, FileHash-SHA256
    """
    cache_key = f"otx_ioc_{ioc_type}_{ioc_value}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    type_map = {
        "IPv4": f"indicators/IPv4/{ioc_value}/general",
        "domain": f"indicators/domain/{ioc_value}/general",
        "hostname": f"indicators/hostname/{ioc_value}/general",
        "url": f"indicators/url/{ioc_value}/general",
        "FileHash-MD5": f"indicators/file/{ioc_value}/general",
        "FileHash-SHA256": f"indicators/file/{ioc_value}/general",
    }

    endpoint = type_map.get(ioc_type)
    if not endpoint:
        return {"error": f"Unsupported IOC type: {ioc_type}"}

    try:
        response = requests.get(
            f"{OTX_BASE}/{endpoint}",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        _cache_set(cache_key, data)
        return data
    except requests.RequestException as e:
        return {"error": str(e)}


def otx_extract_iocs(pulses: list[dict]) -> list[dict]:
    iocs = []
    for pulse in pulses:
        for indicator in pulse.get("indicators", []):
            iocs.append({
                "value": indicator.get("indicator"),
                "type": indicator.get("type"),
                "source": "OTX",
                "pulse_name": pulse.get("name"),
                "pulse_id": pulse.get("id"),
                "tags": pulse.get("tags", []),
                "created": indicator.get("created"),
            })
    return iocs


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────

def abuseipdb_check_ip(ip: str) -> dict:
    cache_key = f"abuseipdb_{ip}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY not set in .env")

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        result = {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "unknown"),
            "isp": data.get("isp", "unknown"),
            "is_tor": data.get("isTor", False),
            "usage_type": data.get("usageType", "unknown"),
            "last_reported": data.get("lastReportedAt"),
            "source": "AbuseIPDB",
        }
        _cache_set(cache_key, result)
        return result
    except requests.RequestException as e:
        return {"ip": ip, "error": str(e), "source": "AbuseIPDB"}


def abuseipdb_blacklist(limit: int = 100, min_score: int = 90) -> list[dict]:
    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY not set in .env")

    cache_key = f"abuseipdb_blacklist_{limit}_{min_score}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE}/blacklist",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            params={
                "limit": limit,
                "confidenceMinimum": min_score,
            },
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("data", [])
        _cache_set(cache_key, data)
        return data
    except requests.RequestException as e:
        raise RuntimeError(f"AbuseIPDB blacklist request failed: {e}") from e


# ─── URLhaus ──────────────────────────────────────────────────────────────────

def urlhaus_lookup_url(url: str) -> dict:
    cache_key = f"urlhaus_url_{url}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        response = requests.post(
            f"{URLHAUS_BASE}/url/",
            data={"url": url},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        data["source"] = "URLhaus"
        _cache_set(cache_key, data)
        return data
    except requests.RequestException as e:
        return {"error": str(e), "source": "URLhaus"}


def urlhaus_lookup_host(host: str) -> dict:
    cache_key = f"urlhaus_host_{host}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        response = requests.post(
            f"{URLHAUS_BASE}/host/",
            data={"host": host},
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        data["source"] = "URLhaus"
        _cache_set(cache_key, data)
        return data
    except requests.RequestException as e:
        return {"error": str(e), "source": "URLhaus"}


def urlhaus_recent_urls(limit: int = 20) -> list[dict]:
    cache_key = f"urlhaus_recent_{limit}"
    cached = _cache_get(cache_key)
    if cached:
        return cached

    try:
        response = requests.get(
            f"{URLHAUS_BASE}/urls/recent/limit/{limit}/",
            timeout=15,
        )
        response.raise_for_status()
        data = response.json().get("urls", [])
        _cache_set(cache_key, data)
        return data
    except requests.RequestException as e:
        return []