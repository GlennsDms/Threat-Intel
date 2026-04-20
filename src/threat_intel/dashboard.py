import streamlit as st
import pandas as pd
import json
from datetime import datetime, timezone
from pathlib import Path

from threat_intel.feeds import (
    otx_get_subscribed_pulses,
    otx_extract_iocs,
    abuseipdb_blacklist,
    urlhaus_recent_urls,
    abuseipdb_check_ip,
    otx_lookup_ioc,
    urlhaus_lookup_host,
)
from threat_intel.correlator import correlate, top_iocs, summary_stats
from threat_intel.summarizer import generate_report
from threat_intel.alerts import dispatch
from threat_intel.exporter import to_json, to_stix

st.set_page_config(
    page_title="Threat Intel Dashboard",
    page_icon=":shield:",
    layout="wide",
)

st.title(":shield: Threat Intelligence Dashboard")
st.caption("Aggregates IOCs from OTX, AbuseIPDB, and URLhaus")

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("Settings")
    pulse_limit = st.slider("OTX pulses to fetch", 1, 50, 10)
    blacklist_limit = st.slider("AbuseIPDB blacklist size", 10, 200, 50)
    urlhaus_limit = st.slider("URLhaus recent URLs", 5, 50, 20)
    run_llm = st.checkbox("Generate LLM report", value=True)
    run_button = st.button("Fetch & Analyze", type="primary")

    st.divider()
    st.header("IOC Lookup")
    lookup_value = st.text_input("IOC value (IP, domain, hash)")
    lookup_type = st.selectbox(
        "Type",
        ["IPv4", "domain", "hostname", "url", "FileHash-MD5", "FileHash-SHA256"]
    )
    lookup_button = st.button("Look up")

# ─── IOC Lookup ───────────────────────────────────────────────────────────────

if lookup_button and lookup_value:
    st.subheader(f"Lookup: {lookup_value}")
    cols = st.columns(3)

    with cols[0]:
        st.markdown("**OTX**")
        try:
            result = otx_lookup_ioc(lookup_type, lookup_value)
            pulse_count = result.get("pulse_info", {}).get("count", 0)
            st.metric("Pulse count", pulse_count)
        except Exception as e:
            st.error(f"OTX failed: {e}")

    with cols[1]:
        if lookup_type == "IPv4":
            st.markdown("**AbuseIPDB**")
            try:
                abuse = abuseipdb_check_ip(lookup_value)
                st.metric("Abuse score", f"{abuse.get('abuse_score')}%")
                st.write(f"Reports: {abuse.get('total_reports')}")
                st.write(f"Country: {abuse.get('country')}")
                st.write(f"ISP: {abuse.get('isp')}")
            except Exception as e:
                st.error(f"AbuseIPDB failed: {e}")

    with cols[2]:
        if lookup_type in ["domain", "hostname"]:
            st.markdown("**URLhaus**")
            try:
                urlhaus = urlhaus_lookup_host(lookup_value)
                st.write(f"Status: {urlhaus.get('query_status')}")
                st.write(f"URLs found: {len(urlhaus.get('urls', []))}")
            except Exception as e:
                st.error(f"URLhaus failed: {e}")

        if lookup_type == "url":
            st.markdown("**URLhaus**")
            try:
                from threat_intel.feeds import urlhaus_lookup_url
                urlhaus = urlhaus_lookup_url(lookup_value)
                st.write(f"Status: {urlhaus.get('query_status')}")
                st.write(f"Threat: {urlhaus.get('threat', 'unknown')}")
            except Exception as e:
                st.error(f"URLhaus failed: {e}")

# ─── Main analysis ────────────────────────────────────────────────────────────

if run_button:
    all_iocs = []

    with st.spinner("Fetching OTX pulses..."):
        try:
            pulses = otx_get_subscribed_pulses(limit=pulse_limit)
            otx_iocs = otx_extract_iocs(pulses)
            all_iocs += otx_iocs
            st.success(f"OTX: {len(otx_iocs)} IOCs from {len(pulses)} pulses")
        except Exception as e:
            st.error(f"OTX failed: {e}")

    with st.spinner("Fetching AbuseIPDB blacklist..."):
        try:
            abuse_ips = abuseipdb_blacklist(limit=blacklist_limit)
            abuse_iocs = [
                {
                    "value": e.get("ipAddress"),
                    "type": "IPv4",
                    "source": "AbuseIPDB",
                    "abuse_score": e.get("abuseConfidenceScore", 0),
                    "country": e.get("countryCode"),
                    "total_reports": e.get("totalReports", 0),
                    "tags": [],
                }
                for e in abuse_ips if e.get("ipAddress")
            ]
            all_iocs += abuse_iocs
            st.success(f"AbuseIPDB: {len(abuse_iocs)} IPs")
        except (ValueError, RuntimeError) as e:
            st.error(f"AbuseIPDB error: {e}")
            st.stop()
        except Exception as e:
            st.error(f"AbuseIPDB unexpected error: {e}")
            st.stop()

    with st.spinner("Fetching URLhaus URLs..."):
        try:
            recent = urlhaus_recent_urls(limit=urlhaus_limit)
            urlhaus_iocs = [
                {
                    "value": u.get("url"),
                    "type": "url",
                    "source": "URLhaus",
                    "tags": u.get("tags", []) or [],
                    "country": None,
                }
                for u in recent if u.get("url")
            ]
            all_iocs += urlhaus_iocs
            st.success(f"URLhaus: {len(urlhaus_iocs)} URLs")
        except Exception as e:
            st.error(f"URLhaus failed: {e}")

    if not all_iocs:
        st.error("No IOCs collected. Check your API keys in .env")
        st.stop()

    with st.spinner("Correlating..."):
        correlated = correlate(all_iocs)
        stats = summary_stats(correlated)
        top = top_iocs(correlated, n=20)

    st.session_state["correlated"] = correlated
    st.session_state["stats"] = stats
    st.session_state["top"] = top

# ─── Results (persists across button clicks) ──────────────────────────────────

if "correlated" in st.session_state:
    correlated = st.session_state["correlated"]
    stats = st.session_state["stats"]
    top = st.session_state["top"]

    st.divider()
    st.subheader("Summary")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total IOCs", stats["total_iocs"])
    c2.metric("Unique values", stats["unique_iocs"])
    c3.metric("Cross-source", stats["cross_source_matches"])
    c4.metric("High confidence", stats["high_confidence_count"])

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("IOC Types")
        type_df = pd.DataFrame(
            list(stats["by_type"].items()), columns=["Type", "Count"]
        ).sort_values("Count", ascending=False)
        st.bar_chart(type_df.set_index("Type"))

    with col2:
        st.subheader("Top Countries")
        if stats["top_countries"]:
            country_df = pd.DataFrame(
                list(stats["top_countries"].items()), columns=["Country", "Count"]
            ).sort_values("Count", ascending=False)
            st.bar_chart(country_df.set_index("Country"))

    st.subheader("Top IOCs by Risk Score")
    top_df = pd.DataFrame(top)
    if not top_df.empty:
        top_df["sources"] = top_df["sources"].apply(lambda x: ", ".join(x))
        top_df["tags"] = top_df["tags"].apply(lambda x: ", ".join(x[:3]) if x else "")
        st.dataframe(
            top_df[["value", "type", "risk_score", "sources", "country", "tags"]],
            use_container_width=True,
        )

    if run_llm:
        st.divider()
        st.subheader("Executive Report")
        with st.spinner("Generating report with LLM..."):
            try:
                report = generate_report(correlated, top, stats)
                st.markdown(report)
            except Exception as e:
                st.error(f"LLM failed: {e}")

    st.divider()
    col_alert, col_export = st.columns(2)

    with col_alert:
        st.subheader("Alerts")
        if st.button("Send alerts"):
            results = dispatch(top, stats)
            if results["slack"]:
                st.success("Slack alert sent")
            else:
                st.warning("Slack not configured or no high-confidence IOCs")
            if results["email"]:
                st.success("Email alert sent")
            else:
                st.warning("Email not configured or no high-confidence IOCs")

    with col_export:
        st.subheader("Export")
        if st.button("Export JSON + STIX"):
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            json_path = Path(f"exports/report_{ts}.json")
            stix_path = Path(f"exports/report_{ts}.stix.json")
            to_json(correlated, top, stats, json_path)
            to_stix(top, stix_path)
            st.success("Files saved to exports/")

            st.download_button(
                label="Download JSON",
                data=json_path.read_text(),
                file_name=json_path.name,
                mime="application/json",
            )
            st.download_button(
                label="Download STIX",
                data=stix_path.read_text(),
                file_name=stix_path.name,
                mime="application/json",
            )