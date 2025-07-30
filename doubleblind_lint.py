#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
doubleblind_lint.py — Standalone CLI to audit PDFs for double‑blind submissions.

What it checks (without modifying the PDF):
- Info dictionary (Title, Author, etc.), XMP packet
- Trailer IDs, version, encryption
- Embedded files/attachments
- Fonts
- XObjects: Form (common for PDF figures) and Image; parses any /Metadata they carry
- Heuristic PII scan (opt-in via --scan-pii): emails, ORCIDs, phone-like strings,
  "corresponding author"/affiliation cues, and EU project markers (Horizon/HEU/FP7/ERC/MSCA/COST, grant numbers).
- Links (including mailto:) and outline/bookmark titles

USAGE
------
  python doubleblind_lint.py INPUT.pdf [OUTPUT.json] [options]

Examples:
  python doubleblind_lint.py paper.pdf --pretty
  python doubleblind_lint.py paper.pdf out.json --scan-pii --progress
  python doubleblind_lint.py paper.pdf --scan-pii --dump-attachments out_dir --fail-on-findings

Exit codes:
  0 = ok
  1 = unexpected error
  2 = encrypted pdf (password needed) or general PDF parse error
  3 = findings present and --fail-on-findings was passed

Dependencies:
  pip install pikepdf lxml pdfminer.six tqdm
  (tqdm is optional; used for progress bar/spinner)

Contribution note:
  The PII/EU scanning section is intentionally easy to extend. See the "DETECTORS"
  block below: add patterns or new detector functions, and they will be included
  automatically by scan_text_pages().
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from decimal import Decimal

# ---------- Optional progress utilities ----------

def _progress_phase(msg, enable=True):
    if not enable:
        return lambda x: x
    try:
        from tqdm import tqdm  # type: ignore
        tqdm.write(str(msg))
        return lambda it, **kw: tqdm(it, desc=msg, **kw)
    except Exception:
        print(msg, file=sys.stderr)
        return lambda it, **kw: it

def _progress_note(msg, enable=True):
    if not enable:
        return
    try:
        from tqdm import tqdm  # type: ignore
        tqdm.write(str(msg))
    except Exception:
        print(msg, file=sys.stderr)

# ---------- Import libraries ----------
try:
    import pikepdf
except Exception as e:
    print("ERROR: pikepdf is required. Install with: pip install pikepdf", file=sys.stderr)
    raise

try:
    import lxml.etree as ET
except Exception:
    import xml.etree.ElementTree as ET  # fallback

# ---------- JSON safety ----------

def _json_default(o):
    try:
        import pikepdf as _pp
    except Exception:
        _pp = None
    if isinstance(o, Decimal):
        try: return float(o)
        except Exception: return str(o)
    if _pp is not None and isinstance(o, (_pp.Name, _pp.Object)):
        return str(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)

# ---------- Low-level helpers ----------

def _b2hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def _try_decode_pdfstr(obj):
    try:
        if isinstance(obj, pikepdf.String):
            return str(obj)
        if isinstance(obj, pikepdf.ByteString):
            try:
                return bytes(obj).decode("utf-8", "strict")
            except Exception:
                return bytes(obj).decode("latin-1", "replace")
        if isinstance(obj, (bytes, bytearray)):
            try:
                return bytes(obj).decode("utf-8", "strict")
            except Exception:
                return bytes(obj).decode("latin-1", "replace")
        return str(obj)
    except Exception:
        return repr(obj)

def _name_to_str(obj):
    try:
        if isinstance(obj, pikepdf.Name):
            return str(obj)
    except Exception:
        pass
    return _try_decode_pdfstr(obj)

# ---------- XMP parsing ----------

def _parse_xmp(xmp_bytes: bytes):
    info = {"raw_base64": base64.b64encode(xmp_bytes or b"").decode("ascii"), "fields": {}}
    if not xmp_bytes:
        return info
    try:
        root = ET.fromstring(xmp_bytes)
    except Exception as e:
        info["parse_error"] = f"XMP XML parse failure: {e}"
        return info

    ns = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "xmp": "http://ns.adobe.com/xap/1.0/",
        "pdf": "http://ns.adobe.com/pdf/1.3/",
        "pdfaid": "http://www.aiim.org/pdfa/ns/id/",
        "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
        "xmpRights": "http://ns.adobe.com/xap/1.0/rights/",
    }

    def text_or_none(el):
        if el is None:
            return None
        t = "".join(el.itertext()) if hasattr(el, "itertext") else el.text
        return (t or "").strip() or None

    def find1(path):
        try:
            return root.find(path, ns)
        except Exception:
            return None

    fields = info["fields"]
    fields["dc:title"] = text_or_none(find1(".//dc:title"))
    fields["dc:creator"] = [text_or_none(x) for x in root.findall(".//dc:creator//rdf:li", ns)] or None
    fields["dc:subject"] = [text_or_none(x) for x in root.findall(".//dc:subject//rdf:li", ns)] or None
    fields["xmp:CreateDate"] = text_or_none(find1(".//xmp:CreateDate"))
    fields["xmp:ModifyDate"] = text_or_none(find1(".//xmp:ModifyDate"))
    fields["xmp:MetadataDate"] = text_or_none(find1(".//xmp:MetadataDate"))
    fields["pdf:Producer"] = text_or_none(find1(".//pdf:Producer"))
    fields["pdf:Keywords"] = text_or_none(find1(".//pdf:Keywords"))
    fields["pdfaid:part"] = text_or_none(find1(".//pdfaid:part"))
    fields["pdfaid:conformance"] = text_or_none(find1(".//pdfaid:conformance"))
    fields["xmpRights:Owner"] = [text_or_none(x) for x in root.findall(".//xmpRights:Owner//rdf:li", ns)] or None

    try:
        flat = {}
        for el in root.iter():
            tag = el.tag
            if isinstance(tag, str):
                local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
                val = (el.text or "").strip()
                if val:
                    flat.setdefault(local, []).append(val)
        if flat:
            fields["_flat_sample"] = {k: (v[0] if len(v) == 1 else v[:5]) for k, v in flat.items()}
    except Exception:
        pass

    return info

# ---------- Metadata traversal ----------

def _get_catalog(pdf):
    root = None
    try:
        root = getattr(pdf, "root")
    except Exception:
        root = None
    if root is None:
        try:
            root = pdf.trailer.get("/Root", None)
        except Exception:
            root = None
    return root

def _normalize_trailer_ids(pdf):
    try:
        arr = pdf.trailer.get("/ID", None)
        if not arr:
            return None
        vals = []
        for x in arr:
            try:
                b = None
                if isinstance(x, pikepdf.ByteString):
                    b = bytes(x)
                elif isinstance(x, (bytes, bytearray)):
                    b = bytes(x)
                elif isinstance(x, pikepdf.String):
                    try:
                        b = bytes(x)
                    except Exception:
                        s = str(x)
                        try: b = s.encode("latin-1", "ignore")
                        except Exception: b = s.encode("utf-8", "ignore")
                else:
                    s = str(x)
                    try: b = s.encode("latin-1", "ignore")
                    except Exception: b = s.encode("utf-8", "ignore")
                vals.append({"hex": _b2hex(b) if b is not None else None, "repr": str(x)})
            except Exception:
                vals.append({"hex": None, "repr": repr(x)})
        return {"original": vals[0] if len(vals) > 0 else None,
                "updated": vals[1] if len(vals) > 1 else None}
    except Exception:
        return None

def _dict_from_docinfo(docinfo):
    out = {}
    for k, v in docinfo.items():
        try:
            key = str(k)
            if key.startswith("/"):
                key = key[1:]
        except Exception:
            key = repr(k)
        out[key] = _try_decode_pdfstr(v)
    return out

def _inspect_xobjects_and_images(pdf):
    visited = set()
    forms, images = [], []

    for page_idx, page in enumerate(pdf.pages, start=1):
        res = page.get("/Resources", {})
        if not isinstance(res, pikepdf.Dictionary):
            continue
        xobjs = res.get("/XObject", {})
        if not isinstance(xobjs, pikepdf.Dictionary):
            continue
        for name, obj in xobjs.items():
            try:
                if not isinstance(obj, pikepdf.Object):
                    continue
                key = obj.objgen
                if key in visited:
                    continue
                visited.add(key)

                subtype = obj.get("/Subtype", None)
                if subtype == pikepdf.Name("/Form"):
                    bbox = obj.get("/BBox", None)
                    matrix = obj.get("/Matrix", None)
                    entry = {
                        "on_page": page_idx,
                        "name": str(name),
                        "obj": f"{key[0]} {key[1]} R",
                        "BBox": [float(v) for v in bbox] if bbox is not None else None,
                        "Matrix": [float(v) for v in matrix] if matrix is not None else None,
                        "Resources_keys": sorted([str(k) for k in (obj.get("/Resources", {}) or {}).keys()]),
                        "has_Metadata": bool(obj.get("/Metadata", None)),
                    }
                    md = obj.get("/Metadata", None)
                    if isinstance(md, pikepdf.Stream):
                        entry["xmp"] = _parse_xmp(md.read_bytes())
                    forms.append(entry)

                elif subtype == pikepdf.Name("/Image"):
                    w = obj.get("/Width", None)
                    h = obj.get("/Height", None)
                    colorspace = obj.get("/ColorSpace", None)
                    bpc = obj.get("/BitsPerComponent", None)
                    filt = obj.get("/Filter", None)
                    if isinstance(filt, pikepdf.Array):
                        filt = [str(x) for x in filt]
                    elif isinstance(filt, pikepdf.Name):
                        filt = [str(filt)]
                    entry = {
                        "on_page": page_idx,
                        "name": str(name),
                        "obj": f"{key[0]} {key[1]} R",
                        "width": int(w) if w is not None else None,
                        "height": int(h) if h is not None else None,
                        "bits_per_component": int(bpc) if bpc is not None else None,
                        "color_space": _name_to_str(colorspace) if colorspace else None,
                        "filters": filt,
                        "has_Metadata": bool(obj.get("/Metadata", None)),
                    }
                    md = obj.get("/Metadata", None)
                    if isinstance(md, pikepdf.Stream):
                        entry["xmp"] = _parse_xmp(md.read_bytes())
                    images.append(entry)
            except Exception:
                continue

    return {"form_xobjects": forms, "image_xobjects": images}

def _iter_embedded_files(pdf):
    results = []
    try:
        catalog = _get_catalog(pdf)
        names = catalog.get("/Names", {}).get("/EmbeddedFiles", {}).get("/Names", None) if catalog else None
        if isinstance(names, pikepdf.Array):
            it = iter(names)
            for name_obj, fs in zip(it, it):
                try:
                    name = _try_decode_pdfstr(name_obj)
                    ef = fs.get("/EF", {})
                    f_stream = ef.get("/F", None) or ef.get("/UF", None)
                    desc = fs.get("/Desc", None)
                    filename = _try_decode_pdfstr(fs.get("/UF", None) or fs.get("/F", None) or name)
                    size = md5 = None
                    if isinstance(f_stream, pikepdf.Stream):
                        data = f_stream.read_bytes()
                        size = len(data); md5 = hashlib.md5(data).hexdigest()
                    results.append({
                        "source": "Names.EmbeddedFiles",
                        "display_name": name,
                        "filename": filename,
                        "description": _try_decode_pdfstr(desc) if desc else None,
                        "size": size,
                        "md5": md5,
                    })
                except Exception:
                    continue
    except Exception:
        pass

    try:
        for page_idx, page in enumerate(pdf.pages, start=1):
            annots = page.get("/Annots", None)
            if not isinstance(annots, pikepdf.Array):
                continue
            for annot in annots:
                try:
                    if annot.get("/Subtype", None) != pikepdf.Name("/FileAttachment"):
                        continue
                    fs = annot.get("/FS", None)
                    if not fs:
                        continue
                    ef = fs.get("/EF", {})
                    f_stream = ef.get("/F", None) or ef.get("/UF", None)
                    filename = _try_decode_pdfstr(fs.get("/UF", None) or fs.get("/F", None))
                    desc = fs.get("/Desc", None)
                    size = md5 = None
                    if isinstance(f_stream, pikepdf.Stream):
                        data = f_stream.read_bytes()
                        size = len(data); md5 = hashlib.md5(data).hexdigest()
                    results.append({
                        "source": f"Annot.FileAttachment@page{page_idx}",
                        "display_name": filename,
                        "filename": filename,
                        "description": _try_decode_pdfstr(desc) if desc else None,
                        "size": size,
                        "md5": md5,
                    })
                except Exception:
                    continue
    except Exception:
        pass

    return results

def _dump_embedded_files(pdf, outdir, items):
    os.makedirs(outdir, exist_ok=True)
    dumped = []

    try:
        catalog = _get_catalog(pdf)
        names = catalog.get("/Names", {}).get("/EmbeddedFiles", {}).get("/Names", None) if catalog else None
        if isinstance(names, pikepdf.Array):
            it = iter(names)
            for name_obj, fs in zip(it, it):
                try:
                    ef = fs.get("/EF", {})
                    f_stream = ef.get("/F", None) or ef.get("/UF", None)
                    if not isinstance(f_stream, pikepdf.Stream): 
                        continue
                    data = f_stream.read_bytes()
                    md5 = hashlib.md5(data).hexdigest()
                    match = next((x for x in items if x.get("md5") == md5), None)
                    if not match: 
                        continue
                    filename = match.get("filename") or _try_decode_pdfstr(name_obj) or f"file_{md5}"
                    filename = "".join(c for c in filename if c not in "\\/:*?\"<>|").strip() or f"file_{md5}"
                    path = os.path.join(outdir, filename)
                    base, ext = os.path.splitext(path); k = 1
                    while os.path.exists(path):
                        path = f"{base}({k}){ext}"; k += 1
                    with open(path, "wb") as f: f.write(data)
                    dumped.append(path)
                except Exception:
                    continue
    except Exception:
        pass

    try:
        for page in pdf.pages:
            annots = page.get("/Annots", None)
            if not isinstance(annots, pikepdf.Array): 
                continue
            for annot in annots:
                try:
                    if annot.get("/Subtype", None) != pikepdf.Name("/FileAttachment"): 
                        continue
                    fs = annot.get("/FS", None)
                    ef = fs.get("/EF", {})
                    f_stream = ef.get("/F", None) or ef.get("/UF", None)
                    if not isinstance(f_stream, pikepdf.Stream): 
                        continue
                    data = f_stream.read_bytes()
                    md5 = hashlib.md5(data).hexdigest()
                    match = next((x for x in items if x.get("md5") == md5), None)
                    if not match: 
                        continue
                    filename = match.get("filename") or f"file_{md5}"
                    filename = "".join(c for c in filename if c not in "\\/:*?\"<>|").strip() or f"file_{md5}"
                    path = os.path.join(outdir, filename)
                    base, ext = os.path.splitext(path); k = 1
                    while os.path.exists(path):
                        path = f"{base}({k}){ext}"; k += 1
                    with open(path, "wb") as f: f.write(data)
                    dumped.append(path)
                except Exception:
                    continue
    except Exception:
        pass

    return dumped

# ---------- TEXT EXTRACTION & SCANNERS ----------

# Heuristic PII patterns
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
ORCID_RE = re.compile(r"\b(?:https?://)?(?:orcid\.org/)?\d{4}-\d{4}-\d{4}-\d{3}[0-9X]\b", re.I)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{6,}\d)(?!\d)")
CORRESPONDING_HINT_RE = re.compile(r"\b(corresponding author|affiliation|university|department|address)\b", re.I)

# EU programme markers
HORIZON_RE = re.compile(r"\b(Horizon(?:\s*2020)?|Horizon\s*Europe|H2020|HEU)\b", re.I)
FP7_RE = re.compile(r"\bFP7(?:[-\s][A-Z]+)?\b", re.I)
ERC_RE = re.compile(r"\bERC(?:\b|[-\s][A-Z]+)\b", re.I)
MSCA_RE = re.compile(r"\b(MSCA|Marie\s*-?\s*Sk(?:ł|l)odowska-?\s*Curie)\b", re.I)
COST_RE = re.compile(r"\bCOST\s+Action\s+(?:CA)?\d{4,5}\b|\bCA\d{4,5}\b", re.I)
GRANT_AGREEMENT_RE = re.compile(r"\b(grant\s+agreement|agreement|grant)\s*(?:No\.?|number|n\.)?\s*([0-9]{5,8})\b", re.I)

# --- DETECTOR REGISTRY (easy to contribute) ---
# To add a new detector, append a dict with:
#   name: unique label
#   regex: compiled pattern
#   handler: optional callable (m, page, text) -> dict to push into 'eu_markers' or a dedicated list
# You can also add new lists to the results structure in scan_text_pages()

DETECTORS = [
    {"name": "EMAIL", "regex": EMAIL_RE, "target": "emails"},
    {"name": "ORCID", "regex": ORCID_RE, "target": "orcids"},
    {"name": "PHONE", "regex": PHONE_RE, "target": "phones",
     "filter": lambda s: sum(ch.isdigit() for ch in s) >= 7},
    {"name": "HORIZON", "regex": HORIZON_RE, "target": "eu_markers", "normalize": lambda s: {"type": "HORIZON", "value": s}},
    {"name": "FP7", "regex": FP7_RE, "target": "eu_markers", "normalize": lambda s: {"type": "FP7", "value": s}},
    {"name": "ERC", "regex": ERC_RE, "target": "eu_markers", "normalize": lambda s: {"type": "ERC", "value": s}},
    {"name": "MSCA", "regex": MSCA_RE, "target": "eu_markers", "normalize": lambda s: {"type": "MSCA", "value": s}},
    {"name": "COST", "regex": COST_RE, "target": "eu_markers", "normalize": lambda s: {"type": "COST", "value": s}},
    {"name": "GRANT_AGREEMENT", "regex": GRANT_AGREEMENT_RE, "target": "eu_markers",
     "normalize": lambda s, m=None: {"type": "GRANT_AGREEMENT", "value": s, "grant_no": (m.group(2) if m else None)}},
    # Keyword hint (not a regex detector into a list, but we keep as special below)
]

def extract_text_by_page(path, progress=False):
    from pdfminer.high_level import extract_pages
    from pdfminer.layout import LTTextBox, LTTextLine
    texts = {}
    phase = _progress_phase("Extracting page text…", progress)
    for i, page_layout in phase(enumerate(extract_pages(path), start=1)):
        parts = []
        for el in page_layout:
            if isinstance(el, (LTTextBox, LTTextLine)):
                parts.append(el.get_text())
        page_text = "".join(parts)
        if page_text.strip():
            texts[i] = page_text
    return texts

def _snip(text, start, end, margin=60):
    s = max(0, start - margin)
    e = min(len(text), end + margin)
    return text[s:e]

def scan_text_pages(texts_by_page, progress=False):
    results = {"emails": [], "orcids": [], "phones": [], "keyword_hits": [],
               "eu_markers": [], "eu_grant_numbers": [], "eu_programmes": []}
    grant_numbers = set()
    programmes = set()

    phase = _progress_phase("Scanning for PII/EU markers…", progress)
    for p, raw in phase(list(texts_by_page.items())):
        txt = " ".join(raw.split())  # normalize whitespace

        # Keyword cue
        kh = CORRESPONDING_HINT_RE.search(txt)
        if kh:
            results["keyword_hits"].append({"page": p, "context": _snip(txt, kh.start(), kh.end())})

        # Registered detectors
        for det in DETECTORS:
            name = det["name"]
            rex = det["regex"]
            target = det["target"]
            normalize = det.get("normalize")
            flt = det.get("filter")
            for m in rex.finditer(txt):
                value = m.group(0)
                if flt and not flt(value):
                    continue
                base = {"page": p, "value": value, "context": _snip(txt, m.start(), m.end())}
                if normalize:
                    extra = normalize(value, m) if normalize.__code__.co_argcount >= 2 else normalize(value)
                    base.update(extra)
                results[target].append(base)
                if target == "eu_markers":
                    if base.get("type") in {"HORIZON","FP7","ERC","MSCA","COST"}:
                        programmes.add(base.get("type"))
                    if base.get("type") == "GRANT_AGREEMENT" and base.get("grant_no"):
                        grant_numbers.add(base["grant_no"])

    results["eu_grant_numbers"] = sorted(grant_numbers)
    results["eu_programmes"] = sorted(programmes)
    return results

def collect_links_and_bookmarks(path):
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
                def walk(node, depth=0, seen=None):
                    if seen is None: seen = set()
                    if not isinstance(node, pikepdf.Dictionary): return
                    if node.objgen in seen: return
                    seen.add(node.objgen)
                    title = node.get("/Title", None)
                    if title:
                        links["outline_titles"].append({"depth": depth, "title": _try_decode_pdfstr(title)})
                    first = node.get("/First", None)
                    next_ = node.get("/Next", None)
                    if first: walk(first, depth+1, seen)
                    if next_: walk(next_, depth, seen)
                walk(outlines, 0, set())
        except Exception:
            pass
    return links

# ---------- Main extraction ----------

def extract_metadata(path, dump_attachments_dir=None, progress=False):
    report = {}
    with pikepdf.open(path, allow_overwriting_input=False) as pdf:
        report["pdf_version"] = str(pdf.pdf_version)
        report["is_encrypted"] = pdf.is_encrypted
        report["linearization"] = "unknown"
        report["trailer_ids"] = _normalize_trailer_ids(pdf)

        try:
            report["info_dict"] = _dict_from_docinfo(pdf.docinfo)
        except Exception as e:
            report["info_dict_error"] = f"{e}"

        # XMP
        try:
            md_stream = None
            catalog = _get_catalog(pdf)
            if isinstance(catalog, pikepdf.Dictionary):
                md_stream = catalog.get("/Metadata", None)
            if isinstance(md_stream, pikepdf.Stream):
                report["xmp"] = _parse_xmp(md_stream.read_bytes())
            else:
                xmp_data = None
                try:
                    with pdf.open_metadata() as x:
                        xml = getattr(x, "xml_bytes", None)
                        if xml:
                            xmp_data = bytes(xml)
                        else:
                            s = str(x)
                            xmp_data = s.encode("utf-8", "ignore")
                except Exception:
                    xmp_data = None
                report["xmp"] = _parse_xmp(xmp_data) if xmp_data else None
        except Exception as e:
            report["xmp_error"] = f"{e}"

        # Embedded files
        try:
            emb = _iter_embedded_files(pdf)
            report["embedded_files"] = emb
        except Exception as e:
            report["embedded_files_error"] = f"{e}"

        if dump_attachments_dir:
            try:
                dumped = _dump_embedded_files(pdf, dump_attachments_dir, report.get("embedded_files", []))
                report["attachments_dumped_to"] = dumped
            except Exception as e:
                report["attachments_dump_error"] = f"{e}"

        # Fonts
        try:
            report["fonts"] = []
            # collect once per page to avoid huge lists; still de-duplicated by object
            report["fonts"] = _collect_fonts(pdf)
        except Exception as e:
            report["fonts_error"] = f"{e}"

        # XObjects
        try:
            report["xobjects"] = _inspect_xobjects_and_images(pdf)
        except Exception as e:
            report["xobjects_error"] = f"{e}"

        # Convenience
        producer = (report.get("info_dict", {}) or {}).get("Producer") or \
                   ((report.get("xmp") or {}).get("fields") or {}).get("pdf:Producer")
        report["producer_hint"] = producer

    return report

def _collect_fonts(pdf):
    seen = set()
    fonts = []
    for page_idx, page in enumerate(pdf.pages, start=1):
        res = page.get("/Resources", {})
        if not isinstance(res, pikepdf.Dictionary): continue
        fd = res.get("/Font", {})
        if not isinstance(fd, pikepdf.Dictionary): continue
        for name, f in fd.items():
            try:
                key = f.objgen if isinstance(f, pikepdf.Object) else None
                if key and key in seen: continue
                if key: seen.add(key)
                subtype = f.get("/Subtype", None)
                basefont = f.get("/BaseFont", None)
                desc = f.get("/FontDescriptor", {})
                fonts.append({
                    "on_page": page_idx,
                    "name": str(name),
                    "obj": f"{key[0]} {key[1]} R" if key else None,
                    "Subtype": _name_to_str(subtype) if subtype else None,
                    "BaseFont": _name_to_str(basefont) if basefont else None,
                    "Embedded": bool(desc.get("/FontFile") or desc.get("/FontFile2") or desc.get("/FontFile3")),
                })
            except Exception:
                continue
    return fonts

# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="Audit PDFs for double-blind submissions (standalone).")
    ap.add_argument("pdf", help="Input PDF path")
    ap.add_argument("output", nargs="?", help="Optional output JSON file (default: stdout)")
    ap.add_argument("--dump-attachments", metavar="DIR", help="Extract embedded attachments into DIR")
    ap.add_argument("--scan-pii", action="store_true", help="Scan text/links for emails, ORCIDs, phones, EU markers")
    ap.add_argument("--fail-on-findings", action="store_true", help="Exit code 3 if any findings are present")
    ap.add_argument("--progress", dest="progress", action="store_true", help="Show progress bars (default if TTY)")
    ap.add_argument("--no-progress", dest="progress", action="store_false", help="Disable progress display")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.set_defaults(progress=sys.stdout.isatty())
    args = ap.parse_args()

    try:
        report = extract_metadata(args.pdf, dump_attachments_dir=args.dump_attachments, progress=args.progress)

        if args.scan_pii:
            # text extraction + scans
            try:
                texts = extract_text_by_page(args.pdf, progress=args.progress)
                report["pii_text_scan"] = scan_text_pages(texts, progress=args.progress)
            except Exception as e:
                report["pii_scan_error"] = f"text extraction failed: {e}"
            # links & bookmarks
            try:
                report["pii_links_bookmarks"] = collect_links_and_bookmarks(args.pdf)
            except Exception as e:
                report["pii_links_bookmarks_error"] = f"{e}"

            if args.fail_on_findings:
                def _has_findings(rep):
                    if not rep: return False
                    text = rep.get("pii_text_scan") or {}
                    links = rep.get("pii_links_bookmarks") or {}
                    keys = ("emails","orcids","phones","keyword_hits","eu_markers")
                    if any(text.get(k) for k in keys):
                        return True
                    if links.get("mailto_links"):
                        return True
                    return False
                if _has_findings(report):
                    # print JSON then exit with code 3
                    if args.output:
                        data = json.dumps(report, indent=2, ensure_ascii=False, default=_json_default) if args.pretty \
                               else json.dumps(report, separators=(",", ":"), ensure_ascii=False, default=_json_default)
                        with open(args.output, "w", encoding="utf-8") as f: f.write(data)
                        print(f"Wrote findings to {args.output}", file=sys.stderr)
                    else:
                        if args.pretty:
                            print(json.dumps(report, indent=2, ensure_ascii=False, default=_json_default))
                        else:
                            print(json.dumps(report, separators=(",", ":"), ensure_ascii=False, default=_json_default))
                    sys.exit(3)

        # Output
        if args.output:
            data = json.dumps(report, indent=2, ensure_ascii=False, default=_json_default) if args.pretty \
                   else json.dumps(report, separators=(",", ":"), ensure_ascii=False, default=_json_default)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(data)
            print(f"Wrote report to {args.output}")
        else:
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
