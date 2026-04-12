# threat-intel

Pulls threat intelligence from OTX, AbuseIPDB, and URLhaus, correlates the IOCs, and writes an executive report using a local LLM. Also has a Streamlit dashboard if you prefer something visual.

Built to understand how CTI actually works — where IOCs come from, how they get scored, and why most of them are useless without cross-source confirmation.

## What it does

Fetches from three sources:

- **AlienVault OTX** — community threat pulses with IPs, domains, hashes, and URLs
- **AbuseIPDB** — IPs reported for abuse, with confidence scores and report counts
- **URLhaus** — recently observed malicious URLs

Deduplicates everything, scores each IOC by risk, flags the ones that show up in more than one source, and feeds the results to a local LLM to generate a report a security team lead can actually read.

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- [Ollama](https://ollama.com/) running locally with `llama3.2:3b`
- API keys for OTX and AbuseIPDB (both free)

```bash
ollama pull llama3.2:3b
```

## Setup

```bash
git clone https://github.com/<your-username>/threat-intel.git
cd threat-intel

uv venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"

cp .env.example .env
```

Add your keys to `.env`:

```
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
OLLAMA_MODEL=llama3.2:3b
```

## Usage

```bash
# fetch, correlate, generate report
uv run python -m threat_intel.cli run

# skip the LLM if you just want the tables
uv run python -m threat_intel.cli run --no-llm

# pull more data
uv run python -m threat_intel.cli run --pulses 20 --blacklist 100

# look up a single IOC
uv run python -m threat_intel.cli lookup 1.2.3.4 --ioc-type IPv4
uv run python -m threat_intel.cli lookup evil.com --ioc-type domain
```

For the dashboard:

```bash
uv run streamlit run src/threat_intel/dashboard.py
```

Opens in the browser. Sliders to control data volume, a table of top IOCs by risk score, charts by type and country, LLM report at the bottom, and a lookup tool in the sidebar.

## How risk scoring works

Each IOC scores 0–100 based on how many sources reported it, AbuseIPDB confidence and report count, whether it's a Tor exit node or proxy, and OTX tags like malware, ransomware, botnet, c2, apt.

Cross-source confirmation adds the most weight. An IOC seen in only one feed with no reports scores low even if the source flags it. An IOC confirmed by OTX, AbuseIPDB, and URLhaus with 60+ reports scores near 100. Volume and confirmation matter more than any single flag.

## Caching

API responses are cached in `data/cache/` for 6 hours. Repeated runs don't burn rate limits and are much faster. Cache is gitignored.

## Tests

```bash
uv run pytest tests/ -v
```

16 tests covering cache behavior, IOC extraction, correlation logic, risk scoring, and error handling.

## Structure

```
src/threat_intel/
├── feeds.py        # OTX, AbuseIPDB, URLhaus clients
├── correlator.py   # IOC correlation and risk scoring
├── summarizer.py   # LLM report generation
├── dashboard.py    # Streamlit dashboard
└── cli.py          # terminal interface
```

## Stack

`requests` for the API clients, `ollama` for the local LLM, `streamlit` for the dashboard, `typer` and `rich` for the CLI, `pytest` for tests.

## Limitations

Risk scoring is heuristic. URLhaus public API sometimes returns empty results. The LLM report quality depends on how many cross-source matches there are — with mostly single-source IOCs it will be thin. No persistence between runs.

## Roadmap

- MISP integration for private threat sharing feeds
- STIX/TAXII support for structured IOC ingestion
- Historical tracking to detect new vs recurring IOCs over time
- Alerts via Slack or email when high-confidence IOCs appear
- JSON export for SIEM ingestion
