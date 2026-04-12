import pytest
from threat_intel.correlator import correlate, top_iocs, summary_stats, _risk_score


SAMPLE_IOCS = [
    {"value": "1.2.3.4", "type": "IPv4", "source": "OTX", "tags": ["malware"], "abuse_score": 0},
    {"value": "1.2.3.4", "type": "IPv4", "source": "AbuseIPDB", "abuse_score": 90, "total_reports": 60, "tags": []},
    {"value": "evil.com", "type": "domain", "source": "OTX", "tags": ["phishing"], "abuse_score": 0},
    {"value": "5.6.7.8", "type": "IPv4", "source": "AbuseIPDB", "abuse_score": 40, "total_reports": 5, "tags": []},
]


def test_correlate_counts():
    result = correlate(SAMPLE_IOCS)
    assert result["total_iocs"] == 4
    assert result["unique_values"] == 3


def test_correlate_cross_source():
    result = correlate(SAMPLE_IOCS)
    assert "1.2.3.4" in result["cross_source_matches"]
    assert "evil.com" not in result["cross_source_matches"]


def test_correlate_by_type():
    result = correlate(SAMPLE_IOCS)
    assert result["by_type"]["IPv4"] == 3
    assert result["by_type"]["domain"] == 1


def test_top_iocs_sorted_by_risk():
    result = correlate(SAMPLE_IOCS)
    top = top_iocs(result, n=10)
    scores = [ioc["risk_score"] for ioc in top]
    assert scores == sorted(scores, reverse=True)


def test_top_iocs_limit():
    result = correlate(SAMPLE_IOCS)
    top = top_iocs(result, n=2)
    assert len(top) <= 2


def test_risk_score_increases_with_reports():
    low = [{"source": "OTX", "tags": [], "total_reports": 0, "abuse_score": 0}]
    high = [{"source": "OTX", "tags": [], "total_reports": 100, "abuse_score": 0}]
    assert _risk_score(high) > _risk_score(low)


def test_risk_score_capped_at_100():
    entries = [
        {"source": "OTX", "tags": ["malware", "ransomware", "botnet", "c2", "apt"], "total_reports": 999, "abuse_score": 100, "is_tor": True},
        {"source": "AbuseIPDB", "tags": ["phishing"], "total_reports": 999, "abuse_score": 100, "is_tor": True},
    ]
    assert _risk_score(entries) <= 100


def test_summary_stats():
    result = correlate(SAMPLE_IOCS)
    stats = summary_stats(result)
    assert stats["total_iocs"] == 4
    assert stats["unique_iocs"] == 3
    assert stats["cross_source_matches"] == 1
    assert "IPv4" in stats["by_type"]