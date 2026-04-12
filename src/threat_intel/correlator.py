from collections import defaultdict
from datetime import datetime, timezone


def correlate(iocs: list[dict]) -> dict:
    """
    Takes a flat list of IOCs from multiple sources and correlates them.
    Returns a structured report with grouped IOCs, cross-source matches,
    and a risk summary.
    """
    by_value = defaultdict(list)
    by_type = defaultdict(list)

    for ioc in iocs:
        value = ioc.get("value") or ioc.get("ip") or ioc.get("url")
        ioc_type = ioc.get("type", "unknown")

        if not value:
            continue

        by_value[value].append(ioc)
        by_type[ioc_type].append(ioc)

    cross_source = {
        value: entries
        for value, entries in by_value.items()
        if len(set(e.get("source") for e in entries)) > 1
    }

    high_confidence = [
        value for value, entries in by_value.items()
        if _risk_score(entries) >= 75
    ]

    return {
        "total_iocs": len(iocs),
        "unique_values": len(by_value),
        "by_type": {k: len(v) for k, v in by_type.items()},
        "cross_source_matches": {
            value: {
                "sources": list(set(e.get("source") for e in entries)),
                "count": len(entries),
                "risk_score": _risk_score(entries),
                "entries": entries,
            }
            for value, entries in cross_source.items()
        },
        "high_confidence_iocs": high_confidence,
        "iocs_by_value": dict(by_value),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _risk_score(entries: list[dict]) -> int:
    score = 0

    sources = set(e.get("source") for e in entries)
    score += len(sources) * 20

    for entry in entries:
        abuse = entry.get("abuse_score", 0)
        if abuse:
            score += int(abuse * 0.5)

        if entry.get("is_tor"):
            score += 15

        usage = entry.get("usage_type", "")
        if usage in ["VPN Service", "Tor Exit Node", "Proxy"]:
            score += 10

        reports = entry.get("total_reports", 0)
        if reports > 50:
            score += 20
        elif reports > 10:
            score += 10

        tags = entry.get("tags", [])
        malicious_tags = ["malware", "ransomware", "botnet", "phishing", "c2", "apt"]
        score += sum(5 for t in tags if any(m in t.lower() for m in malicious_tags))

    return min(score, 100)


def enrich_with_abuseipdb(
    correlated: dict,
    abuseipdb_results: list[dict],
) -> dict:
    abuse_by_ip = {r["ip"]: r for r in abuseipdb_results if "ip" in r}

    for value, data in correlated["iocs_by_value"].items():
        if value in abuse_by_ip:
            for entry in data:
                entry.update(abuse_by_ip[value])

    return correlated


def top_iocs(correlated: dict, n: int = 10) -> list[dict]:
    scored = []
    for value, entries in correlated["iocs_by_value"].items():
        scored.append({
            "value": value,
            "type": entries[0].get("type", "unknown"),
            "sources": list(set(e.get("source") for e in entries)),
            "risk_score": _risk_score(entries),
            "tags": list(set(
                tag for e in entries for tag in e.get("tags", [])
            )),
            "abuse_score": max(
                (e.get("abuse_score", 0) for e in entries), default=0
            ),
            "country": next(
                (e.get("country") for e in entries if e.get("country")), None
            ),
        })

    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)[:n]


def summary_stats(correlated: dict) -> dict:
    iocs = correlated["iocs_by_value"]
    all_entries = [e for entries in iocs.values() for e in entries]

    countries = defaultdict(int)
    for e in all_entries:
        c = e.get("country")
        if c:
            countries[c] += 1

    sources = defaultdict(int)
    for e in all_entries:
        s = e.get("source")
        if s:
            sources[s] += 1

    return {
        "total_iocs": correlated["total_iocs"],
        "unique_iocs": correlated["unique_values"],
        "cross_source_matches": len(correlated["cross_source_matches"]),
        "high_confidence_count": len(correlated["high_confidence_iocs"]),
        "by_type": correlated["by_type"],
        "top_countries": dict(sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]),
        "by_source": dict(sources),
    }