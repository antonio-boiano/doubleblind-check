# -*- coding: utf-8 -*-
"""
CLI entry for pdf-privacy-scan.
"""
import argparse
import json
import sys
import os
from decimal import Decimal

import pikepdf

from .metadata_extractor import extract_metadata
from .pii_scanner import extract_text_by_page, scan_text_pages, collect_links_and_bookmarks


def _json_default(o):
    if isinstance(o, Decimal):
        try:
            return float(o)
        except Exception:
            return str(o)
    try:
        if isinstance(o, (pikepdf.Name, pikepdf.Object)):
            return str(o)
    except Exception:
        pass
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)


def main():
    ap = argparse.ArgumentParser(description="Extract PDF metadata + optional PII/EU scan.")
    ap.add_argument("pdf", help="Input PDF path")
    ap.add_argument("--dump-attachments", metavar="DIR", help="Extract embedded attachments into DIR")
    ap.add_argument("--scan-pii", action="store_true", help="Run text/link scan for emails, ORCID, phones, EU markers")
    ap.add_argument("--fail-on-findings", action="store_true", help="Exit with non-zero status if any PII/EU markers are found")
    ap.add_argument("--progress", dest="progress", action="store_true", help="Show progress bars (default if TTY)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress display")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.set_defaults(progress=sys.stdout.isatty())
    args = ap.parse_args()

    try:
        report = extract_metadata(args.pdf, dump_attachments_dir=args.dump_attachments)

        if args.scan_pii:
            # Loading/progress: two phases (extract text, then scan)
            texts = None
            if args.progress:
                try:
                    from tqdm import tqdm
                    tqdm.write("Extracting page text…")
                except Exception:
                    print("Extracting page text…", file=sys.stderr)
            try:
                texts = extract_text_by_page(args.pdf)
            except Exception as e:
                report["pii_scan_error"] = f"text extraction failed: {e}"

            if texts is not None:
                show = bool(args.progress)
                if args.progress:
                    try:
                        from tqdm import tqdm
                        tqdm.write("Scanning for PII/EU markers…")
                    except Exception:
                        print("Scanning for PII/EU markers…", file=sys.stderr)
                report["pii_text_scan"] = scan_text_pages(texts, show_progress=show)

            try:
                report["pii_links_bookmarks"] = collect_links_and_bookmarks(args.pdf)
            except Exception as e:
                report["pii_links_bookmarks_error"] = f"{e}"

            if args.fail_on_findings:
                def _has_findings(pi):
                    if not pi: 
                        return False
                    for key in ("emails", "orcids", "phones", "keyword_hits", "eu_markers"):
                        if pi.get(key):
                            return True
                    return False
                if _has_findings(report.get("pii_text_scan")) or report.get("pii_links_bookmarks", {}).get("mailto_links"):
                    # non-zero exit for CI
                    if args.pretty:
                        print(json.dumps(report, indent=2, ensure_ascii=False, default=_json_default))
                    else:
                        print(json.dumps(report, separators=(",", ":"), ensure_ascii=False, default=_json_default))
                    sys.exit(3)

        # Output JSON
        if args.pretty:
            print(json.dumps(report, indent=2, ensure_ascii=False, default=_json_default))
        else:
            print(json.dumps(report, separators=(",", ":"), ensure_ascii=False, default=_json_default))

    except pikepdf.PasswordError:
        print(json.dumps({"error": "PDF is encrypted; a password is required."}))
        sys.exit(2)
    except pikepdf.PdfError as e:
        print(json.dumps({"error": f"{e}"}))
        sys.exit(2)
    except Exception as e:
        print(json.dumps({"error": f"Failed to open or parse PDF: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
