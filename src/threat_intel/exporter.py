import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


STIX_SPEC_VERSION = "2.1"


def to_json(correlated: dict, top_iocs: list[dict], stats: dict, output_path: Path):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "top_iocs": top_iocs,
        "all_iocs": [
            {
                "value": value,
                "entries": entries,
            }
            for value, entries in correlated["iocs_by_value"].items()
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, default=str))


def to_stix(top_iocs: list[dict], output_path: Path):
    """
    Exports top IOCs as a STIX 2.1 bundle.
    Only supports IPv4, domain, url, and file hash types.
    """
    now = datetime.now(timezone.utc).isoformat()
    objects = []

    type_map = {
        "IPv4": ("ipv4-addr", "value"),
        "domain": ("domain-name", "value"),
        "hostname": ("domain-name", "value"),
        "url": ("url", "value"),
        "FileHash-MD5": ("file", None),
        "FileHash-SHA256": ("file", None),
    }

    for ioc in top_iocs:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")

        if ioc_type not in type_map:
            continue

        stix_type, field = type_map[ioc_type]

        if stix_type == "file":
            hash_type = "MD5" if "MD5" in ioc_type else "SHA-256"
            obj = {
                "type": "file",
                "spec_version": STIX_SPEC_VERSION,
                "id": f"file--{uuid.uuid4()}",
                "hashes": {hash_type: value},
            }
        else:
            obj = {
                "type": stix_type,
                "spec_version": STIX_SPEC_VERSION,
                "id": f"{stix_type}--{uuid.uuid4()}",
                field: value,
            }

        objects.append(obj)

        indicator = {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"Malicious {ioc_type}: {value}",
            "indicator_types": ["malicious-activity"],
            "pattern": _stix_pattern(ioc_type, value),
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": ioc.get("risk_score", 0),
            "labels": ioc.get("tags", []),
        }
        objects.append(indicator)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle, indent=2))


def _stix_pattern(ioc_type: str, value: str) -> str:
    patterns = {
        "IPv4": f"[ipv4-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "hostname": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "FileHash-MD5": f"[file:hashes.MD5 = '{value}']",
        "FileHash-SHA256": f"[file:hashes.'SHA-256' = '{value}']",
    }
    return patterns.get(ioc_type, f"[unknown:value = '{value}']")