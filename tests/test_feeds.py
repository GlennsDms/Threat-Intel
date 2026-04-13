import pytest
import requests
from unittest.mock import patch, MagicMock
from pathlib import Path
from threat_intel.feeds import (
    _cache_path,
    _cache_get,
    _cache_set,
    otx_extract_iocs,
    abuseipdb_check_ip,
    abuseipdb_blacklist,
)


# ─── Cache tests ──────────────────────────────────────────────────────────────

def test_cache_path_is_deterministic():
    p1 = _cache_path("some_key")
    p2 = _cache_path("some_key")
    assert p1 == p2


def test_cache_miss_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)
    result = _cache_get("nonexistent_key")
    assert result is None


def test_cache_set_and_get(tmp_path, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)
    payload = {"ip": "1.2.3.4", "score": 95}
    _cache_set("test_key", payload)
    result = _cache_get("test_key")
    assert result == payload


# ─── OTX tests ────────────────────────────────────────────────────────────────

def test_otx_extract_iocs_empty():
    result = otx_extract_iocs([])
    assert result == []


def test_otx_extract_iocs_basic():
    pulses = [
        {
            "name": "Test Pulse",
            "id": "abc123",
            "tags": ["malware", "botnet"],
            "indicators": [
                {"indicator": "1.2.3.4", "type": "IPv4", "created": "2024-01-01"},
                {"indicator": "evil.com", "type": "domain", "created": "2024-01-01"},
            ],
        }
    ]
    result = otx_extract_iocs(pulses)
    assert len(result) == 2
    assert result[0]["value"] == "1.2.3.4"
    assert result[0]["source"] == "OTX"
    assert result[1]["value"] == "evil.com"
    assert result[1]["pulse_name"] == "Test Pulse"


def test_otx_extract_iocs_missing_indicators():
    pulses = [{"name": "Empty Pulse", "id": "xyz", "tags": [], "indicators": []}]
    result = otx_extract_iocs(pulses)
    assert result == []


# ─── AbuseIPDB tests ──────────────────────────────────────────────────────────

@patch("threat_intel.feeds.requests.get")
def test_abuseipdb_check_ip_success(mock_get, tmp_path, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)
    monkeypatch.setattr("threat_intel.feeds.ABUSEIPDB_API_KEY", "fake_key")

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "countryCode": "RU",
            "isp": "Some ISP",
            "isTor": False,
            "usageType": "Data Center",
            "lastReportedAt": "2024-01-01",
        }
    }
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    result = abuseipdb_check_ip("1.2.3.4")
    assert result["abuse_score"] == 87
    assert result["total_reports"] == 42
    assert result["country"] == "RU"
    assert result["source"] == "AbuseIPDB"


@patch("threat_intel.feeds.requests.get")
def test_abuseipdb_check_ip_failure(mock_get, tmp_path, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)
    monkeypatch.setattr("threat_intel.feeds.ABUSEIPDB_API_KEY", "fake_key")

    import requests as req
    mock_get.side_effect = req.exceptions.RequestException("Connection error")

    result = abuseipdb_check_ip("9.9.9.9")
    assert "error" in result
    assert result["source"] == "AbuseIPDB"

def test_abuseipdb_blacklist_raises_without_key(monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.ABUSEIPDB_API_KEY", "")
    with pytest.raises(ValueError, match="ABUSEIPDB_API_KEY"):
        abuseipdb_blacklist()


@patch("threat_intel.feeds.requests.get")
def test_abuseipdb_blacklist_raises_on_request_failure(mock_get, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.ABUSEIPDB_API_KEY", "fake_key")
    mock_get.side_effect = requests.exceptions.RequestException("timeout")
    with pytest.raises(RuntimeError, match="AbuseIPDB blacklist request failed"):
        abuseipdb_blacklist()


@patch("threat_intel.feeds.requests.get")
def test_abuseipdb_blacklist_success(mock_get, tmp_path, monkeypatch):
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)
    monkeypatch.setattr("threat_intel.feeds.ABUSEIPDB_API_KEY", "fake_key")

    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": [
            {"ipAddress": "1.2.3.4", "abuseConfidenceScore": 95, "totalReports": 10, "countryCode": "RU"},
        ]
    }
    mock_response.raise_for_status = MagicMock()
    mock_get.return_value = mock_response

    result = abuseipdb_blacklist(limit=1)
    assert len(result) == 1
    assert result[0]["ipAddress"] == "1.2.3.4"