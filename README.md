# doubleblind-check
**Goal:** check PDFs for double‑blind submission compliance: strip deanonymizing metadata, and flag emails/ORCIDs/phones, links (incl. `mailto:`), bookmarks, and EU funding references (Horizon/ERC/MSCA/COST/FP7 + grant numbers).

## One-file CLI

This repo is a **single Python script** (`doubleblind_lint.py`). No package install is required.

### Install deps

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # pikepdf, lxml, pdfminer.six, tqdm (optional)
```

### Run

```bash
python doubleblind_lint.py INPUT.pdf [OUTPUT.json] [options]
```

Examples:
```bash
# Print JSON to stdout, metadata only
python doubleblind_lint.py paper.pdf --pretty

# Add PII/EU scan and progress, write to a file
python doubleblind_lint.py paper.pdf out.json --scan-pii --progress --pretty

# CI mode: nonzero exit if anything found
python doubleblind_lint.py paper.pdf --scan-pii --fail-on-findings
echo $?   # 3 if findings, 0 otherwise
```

**Useful options**
- `--scan-pii` — run text + links scan for emails, ORCIDs, phone-like strings, EU markers; stores results in `pii_text_scan` and `pii_links_bookmarks`.
- `--progress` / `--no-progress` — show progress (uses `tqdm` if available).
- `--dump-attachments DIR` — extract any embedded files.
- `--fail-on-findings` — exit code 3 if anything sensitive/identifying is detected.

## Contributing to the PII/EU scan

Open `doubleblind_lint.py` and search for **`DETECTORS`**. It’s a simple list of dicts:

```python
DETECTORS = [
    {"name": "EMAIL", "regex": EMAIL_RE, "target": "emails"},
    {"name": "ORCID", "regex": ORCID_RE, "target": "orcids"},
    # ...
    {"name": "GRANT_AGREEMENT", "regex": GRANT_AGREEMENT_RE, "target": "eu_markers",
     "normalize": lambda s, m=None: {"type": "GRANT_AGREEMENT", "value": s, "grant_no": (m.group(2) if m else None)}},
]
```

Add new items to detect more patterns. The scan automatically aggregates:
- `eu_programmes`: unique set of programme types seen (HORIZON, FP7, ERC, MSCA, COST)
- `eu_grant_numbers`: unique list of grant IDs collected

If you need a custom detector that does more than a regex, add your own `normalize` callable; it receives the match string and the `re.Match` object.

## What it checks

- **Metadata**: Info dictionary, XMP (robust), trailer IDs, version/encryption.
- **Structure**: embedded files, fonts, Form/Image XObjects; extracts any XMP linked to XObjects.
- **PII/EU (opt‑in)**: emails, ORCIDs, phone‑like strings, “corresponding author” cues, EU programme names and grant numbers.
- **Links/bookmarks**: page annotations with URIs (`mailto:` flagged) and outline/bookmark titles.

## Limits

- No OCR; scanned PDFs require OCR to see text (can be added).
- Heuristics for phones may over/under‑flag, emails/ORCIDs are reliable.
- Regex‑based EU detection; treat as red‑flags to manually review.


