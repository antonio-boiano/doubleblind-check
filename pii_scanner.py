# -*- coding: utf-8 -*-
"""
PII & EU project marker scanning utilities.
"""
import re
from typing import Dict, Any, Tuple, Optional

# Regex patterns
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ORCID_RE = re.compile(r"\b(?:https?://)?(?:orcid\.org/)?\d{4}-\d{4}-\d{4}-\d{3}[0-9X]\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{6,}\d)(?!\d)")
CORRESPONDING_HINT_RE = re.compile(r"\b(corresponding author|affiliation|university|department|address)\b", re.I)

# EU project markers
HORIZON_RE = re.compile(r"\b(Horizon(?:\s*2020)?|Horizon\s*Europe|H2020|HEU)\b", re.I)
FP7_RE = re.compile(r"\bFP7(?:[-\s][A-Z]+)?\b", re.I)
ERC_RE = re.compile(r"\bERC(?:\b|[-\s][A-Z]+)\b", re.I)
MSCA_RE = re.compile(r"\b(MSCA|Marie\s*-?\s*Sk(?:ł|l)odowska-?\s*Curie)\b", re.I)
COST_RE = re.compile(r"\bCOST\s+Action\s+(?:CA)?\d{4,5}\b|\bCA\d{4,5}\b", re.I)
GRANT_AGREEMENT_RE = re.compile(r"\b(grant\s+agreement|agreement|grant)\s*(?:No\.?|number|n\.)?\s*([0-9]{5,8})\b", re.I)

def _snip(text, start, end, margin=60):
    s = max(0, start - margin)
    e = min(len(text), end + margin)
    return text[s:e]

def extract_text_by_page(path: str) -> Dict[int, str]:
    """Return dict page->text using pdfminer.six."""
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTTextBox, LTTextLine
    texts = {}
    for i, page_layout in enumerate(extract_pages(path), start=1):
        parts = []
        for el in page_layout:
            if isinstance(el, (LTTextBox, LTTextLine)):
                parts.append(el.get_text())
        page_text = "".join(parts)
        if page_text.strip():
            texts[i] = page_text
    return texts

def scan_text_pages(texts_by_page: Dict[int, str], show_progress: bool = False) -> Dict[str, Any]:
    """Scan texts for PII and EU markers. Returns a dict of lists."""
    results = {"emails": [], "orcids": [], "phones": [], "keyword_hits": [],
               "eu_markers": [], "eu_grant_numbers": [], "eu_programmes": []}

    progress_iter = list(texts_by_page.items())
    if show_progress:
        try:
            from tqdm import tqdm
            progress_iter = tqdm(progress_iter, desc="Scanning pages for PII/EU markers")
        except Exception:
            pass  # fallback to plain loop

    grant_numbers = set()
    programmes = set()

    for p, txt in progress_iter:
        snippet_src = " ".join(txt.split())

        for m in EMAIL_RE.finditer(snippet_src):
            results["emails"].append({"page": p, "value": m.group(0), "context": _snip(snippet_src, m.start(), m.end())})

        for m in ORCID_RE.finditer(snippet_src):
            results["orcids"].append({"page": p, "value": m.group(0), "context": _snip(snippet_src, m.start(), m.end())})

        for m in PHONE_RE.finditer(snippet_src):
            s = m.group(0)
            if sum(ch.isdigit() for ch in s) >= 7:
                results["phones"].append({"page": p, "value": s, "context": _snip(snippet_src, m.start(), m.end())})

        kh = CORRESPONDING_HINT_RE.search(snippet_src)
        if kh:
            results["keyword_hits"].append({"page": p, "context": _snip(snippet_src, kh.start(), kh.end())})

        # EU markers
        for lab, rex in [("HORIZON", HORIZON_RE), ("FP7", FP7_RE), ("ERC", ERC_RE), ("MSCA", MSCA_RE), ("COST", COST_RE)]:
            for m in rex.finditer(snippet_src):
                results["eu_markers"].append({"page": p, "type": lab, "value": m.group(0), "context": _snip(snippet_src, m.start(), m.end())})
                programmes.add(lab)

        for m in GRANT_AGREEMENT_RE.finditer(snippet_src):
            grant = m.group(2)
            results["eu_markers"].append({"page": p, "type": "GRANT_AGREEMENT", "value": m.group(0), "grant_no": grant,
                                          "context": _snip(snippet_src, m.start(), m.end())})
            grant_numbers.add(grant)

    results["eu_grant_numbers"] = sorted(grant_numbers)
    results["eu_programmes"] = sorted(programmes)
    return results

def collect_links_and_bookmarks(path: str) -> Dict[str, Any]:
    """Collect annotation URIs (including mailto) and outline titles."""
    import pikepdf
    from .metadata_extractor import _get_catalog, _try_decode_pdfstr
    links = {"annotation_uris": [], "mailto_links": [], "outline_titles": []}
    with pikepdf.open(path, allow_overwriting_input=False) as pdf:
        # Links
        try:
            for page_idx, page in enumerate(pdf.pages, start=1):
                annots = page.get("/Annots", None)
                if not isinstance(annots, pikepdf.Array): 
                    continue
                for annot in annots:
                    try:
                        a = annot.get("/A", None)
                        if not isinstance(a, pikepdf.Dictionary): 
                            continue
                        uri = a.get("/URI", None)
                        if uri:
                            u = _try_decode_pdfstr(uri)
                            entry = {"page": page_idx, "uri": u}
                            links["annotation_uris"].append(entry)
                            if u.lower().startswith("mailto:"):
                                links["mailto_links"].append(entry)
                    except Exception:
                        continue
        except Exception:
            pass
        # Bookmarks
        try:
            catalog = _get_catalog(pdf)
            outlines = catalog.get("/Outlines", None) if catalog else None
            if outlines:
                def walk_outline(node, depth=0, seen=None):
                    if seen is None: 
                        seen = set()
                    if not isinstance(node, pikepdf.Dictionary): 
                        return
                    if node.objgen in seen: 
                        return
                    seen.add(node.objgen)
                    title = node.get("/Title", None)
                    if title:
                        links["outline_titles"].append({"depth": depth, "title": _try_decode_pdfstr(title)})
                    first = node.get("/First", None)
                    next_ = node.get("/Next", None)
                    if first: walk_outline(first, depth+1, seen)
                    if next_: walk_outline(next_, depth, seen)
                walk_outline(outlines, 0, set())
        except Exception:
            pass
    return links
