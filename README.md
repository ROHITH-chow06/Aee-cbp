# AEE-CBP — Automotive Bus Protocol Analyzer

A browser-based engineering tool for inspecting timestamped automotive CAN logs, decoding configured signals, and flagging communication or threshold anomalies.

## Features

- Upload CSV logs and Vector CANalyzer/CANoe ASC traces.
- Normalize timestamps, CAN identifiers, DLC, and payload bytes.
- Decode configurable signals from payload bytes with byte order, scale, offset, and units.
- Detect configured message timeouts, inter-arrival gaps, malformed payloads, and signal threshold breaches.
- Interactive timeline and signal plots, filterable frame/event tables, and CSV exports.
- Includes a small synthetic example dataset for safe experimentation.

## Stack

- Python 3.12+, FastAPI, Pandas
- HTML, CSS, JavaScript, Chart.js
- Vercel Python runtime (FastAPI)

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000.

## CSV format

The analyzer recognizes common column aliases. A minimal CSV can use:

```csv
timestamp,can_id,dlc,data
0.000,0x100,8,10 27 00 00 00 00 00 00
0.010,0x100,8,20 27 00 00 00 00 00 00
```

The `data` field may contain space-separated hex bytes, a compact hex string, or a JSON-style list. Standard Vector ASC data lines are also supported.

## Signal decoding

Signal definitions are configured in the UI:
- CAN ID: decimal or hexadecimal identifier
- Start byte: zero-based byte index
- Length: number of bytes (1–8)
- Byte order: little-endian or big-endian
- Scale and offset: physical value = raw value × scale + offset
- Unit and optional minimum/maximum thresholds

This is a generic byte-aligned decoder, not a complete DBC/ARXML implementation. Bit-level signals, multiplexing, signedness, and OEM-specific conventions should be added explicitly when required. Confirm signal definitions against the correct network specification before drawing engineering conclusions.

## Detection rules

- Message timeout: configure an expected period per CAN ID; gaps above the configured multiple are flagged.
- Signal thresholds: optional minimum and maximum per configured signal.
- Parse errors: malformed records and invalid payloads are reported rather than silently discarded.

A timeout can only be inferred when an expected message period is configured. The tool does not claim that a trace proves a physical vehicle fault. It is an analysis aid, not a safety-critical diagnostic system.

## Security and data handling

Files are processed in-memory for the request and are not intentionally persisted. The API enforces an upload size limit and validates file extensions. Do not upload confidential vehicle traces or personal data to a public deployment without reviewing access controls, retention, and your organization's policies.

## Deploy to Vercel

1. Import this GitHub repository into Vercel.
2. Keep the project root at the repository root.
3. Vercel should detect the FastAPI application in `app.py` and install dependencies from `requirements.txt`.
4. Deploy, then verify the home page and `/health` endpoint.

See the official [Vercel FastAPI guide](https://vercel.com/docs/frameworks/backend/fastapi).

## Disclaimer

This project is intended for educational and engineering analysis. Validate results independently before using them for vehicle decisions.
