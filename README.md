# pdf-privacy-scan

A small, modular toolkit to extract deep metadata from PDFs (especially LaTeX-generated articles)
and perform a heuristic privacy scan for emails, ORCID iDs, phone-like numbers, and **EU project markers**
(e.g., *Horizon 2020/Horizon Europe*, *ERC*, *MSCA*, *COST Action*, and *grant agreement No. 123456*).

## Features

- Info dictionary, XMP, trailer IDs (hex + repr), PDF version/encryption.
- Embedded files (optionally dump them).
- Fonts used.
- XObjects: Form (often PDF figures) and Image; parses any `/Metadata` on them.
- Heuristic PII scan (`--scan-pii`): emails, ORCIDs, phone-like strings, keywords like "corresponding author".
- **EU project detection**: Horizon 2020/Horizon Europe, ERC, MSCA, COST Action, FP7; grant agreement numbers.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
```

## CLI Usage

```bash
python -m pdf_privacy_scan.cli path/to/paper.pdf --pretty
python -m pdf_privacy_scan.cli path/to/paper.pdf --scan-pii --pretty
python -m pdf_privacy_scan.cli path/to/paper.pdf --scan-pii --dump-attachments out_dir --pretty
# Fail CI if anything sensitive is found:
python -m pdf_privacy_scan.cli path/to/paper.pdf --scan-pii --fail-on-findings
```

### Progress display

Use `--progress` (default on for TTY). To suppress: `--no-progress`.

The progress bar shows **page text extraction** and **PII scanning**. If `tqdm` is not installed,
simple step messages will be printed instead.

## Library Usage (integrate `--scan-pii` in your code)

```python
from pdf_privacy_scan.metadata_extractor import extract_metadata
from pdf_privacy_scan.pii_scanner import extract_text_by_page, scan_text_pages, collect_links_and_bookmarks

pdf_path = "paper.pdf"
report = extract_metadata(pdf_path)  # dict

# Enable PII scan
texts = extract_text_by_page(pdf_path)
pii_text = scan_text_pages(texts)  # dict with emails/orcids/phones/eu markers
links = collect_links_and_bookmarks(pdf_path)

report["pii_text_scan"] = pii_text
report["pii_links_bookmarks"] = links
```

## Notes & Limits

- No OCR; image-only pages require an OCR step (can be added on request).
- Heuristics: may miss or over-flag some phones; email/ORCID are reliable.
- EU marker detection is pattern-based; it flags likely acknowledgements and grant codes for review.

## License

MIT
