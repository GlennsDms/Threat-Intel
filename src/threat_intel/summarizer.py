import os
import ollama
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")


def generate_report(correlated: dict, top_iocs: list[dict], stats: dict) -> str:
    prompt = _build_prompt(correlated, top_iocs, stats)
    
    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
        )
        return response["message"]["content"]
    except Exception as e:
        return f"LLM summarization failed: {e}\n\nRaw stats:\n{stats}"


def _build_prompt(correlated: dict, top_iocs: list[dict], stats: dict) -> str:
    top_iocs_text = ""
    for ioc in top_iocs[:10]:
        sources = ", ".join(ioc["sources"])
        tags = ", ".join(ioc["tags"][:5]) if ioc["tags"] else "none"
        top_iocs_text += (
            f"- {ioc['value']} ({ioc['type']}) | "
            f"Risk: {ioc['risk_score']}/100 | "
            f"Sources: {sources} | "
            f"Tags: {tags}\n"
        )

    cross = correlated.get("cross_source_matches", {})
    cross_text = ""
    for value, data in list(cross.items())[:5]:
        cross_text += (
            f"- {value} seen in: {', '.join(data['sources'])} "
            f"(risk score: {data['risk_score']})\n"
        )

    by_type = stats.get("by_type", {})
    type_text = "\n".join(f"  - {k}: {v}" for k, v in by_type.items())

    top_countries = stats.get("top_countries", {})
    country_text = ", ".join(
        f"{c} ({n})" for c, n in list(top_countries.items())[:5]
    )

    prompt = f"""You are a threat intelligence analyst. Based on the following data, write a concise executive report.

The report should:
- Be written for a security team lead, not a technical developer
- Summarize what threats were observed and from where
- Highlight the most critical IOCs and why they matter
- Note any patterns (geographic clusters, cross-source confirmation, specific malware families)
- End with 2-3 concrete recommended actions
- Be direct. No filler. No "In conclusion".

--- DATA ---

Total IOCs collected: {stats['total_iocs']}
Unique IOC values: {stats['unique_iocs']}
Cross-source matches (seen in 2+ feeds): {stats['cross_source_matches']}
High confidence IOCs (risk >= 75): {stats['high_confidence_count']}

IOC breakdown by type:
{type_text}

Top origin countries: {country_text}

Top IOCs by risk score:
{top_iocs_text}

IOCs confirmed by multiple sources:
{cross_text if cross_text else "None"}

--- END DATA ---

Write the executive report now:"""

    return prompt


def format_report_for_terminal(report: str, stats: dict, generated_at: str) -> str:
    divider = "-" * 60
    return f"""
{divider}
  THREAT INTELLIGENCE REPORT
  Generated: {generated_at}
{divider}

{report}

{divider}
  STATS
  Total IOCs:        {stats['total_iocs']}
  Unique values:     {stats['unique_iocs']}
  Cross-source:      {stats['cross_source_matches']}
  High confidence:   {stats['high_confidence_count']}
{divider}
"""