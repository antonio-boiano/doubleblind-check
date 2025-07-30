# -*- coding: utf-8 -*-
"""
Core PDF metadata extraction utilities.
"""
import base64
import binascii
import hashlib
from decimal import Decimal

import pikepdf

try:
    import lxml.etree as ET
except Exception:
    import xml.etree.ElementTree as ET


def _b2hex(b: bytes) -> str:
    import binascii
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
        "pdfxid": "http://www.npes.org/pdfx/ns/id/",
        "xmpMM": "http://ns.adobe.com/xap/1.0/mm/",
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

    # flattened sample
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
                        try:
                            b = s.encode("latin-1", "ignore")
                        except Exception:
                            b = s.encode("utf-8", "ignore")
                else:
                    s = str(x)
                    try:
                        b = s.encode("latin-1", "ignore")
                    except Exception:
                        b = s.encode("utf-8", "ignore")
                vals.append({"hex": _b2hex(b) if b is not None else None, "repr": str(x)})
            except Exception:
                vals.append({"hex": None, "repr": repr(x)})
        return {"original": vals[0] if len(vals) > 0 else None,
                "updated": vals[1] if len(vals) > 1 else None}
    except Exception:
        return None


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

    # FileAttachment annotations
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
    import os
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
                    with open(path, "wb") as f: 
                        f.write(data)
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
                    with open(path, "wb") as f: 
                        f.write(data)
                    dumped.append(path)
                except Exception:
                    continue
    except Exception:
        pass
    return dumped


def _collect_fonts(pdf):
    seen = set()
    fonts = []
    for page_idx, page in enumerate(pdf.pages, start=1):
        res = page.get("/Resources", {})
        if not isinstance(res, pikepdf.Dictionary):
            continue
        fd = res.get("/Font", {})
        if not isinstance(fd, pikepdf.Dictionary):
            continue
        for name, f in fd.items():
            try:
                key = f.objgen if isinstance(f, pikepdf.Object) else None
                if key and key in seen: 
                    continue
                if key: 
                    seen.add(key)
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


def extract_metadata(path, dump_attachments_dir=None):
    """
    Open PDF and return a dict with metadata & structure. Optionally dump attachments.
    """
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

        # XMP (robust)
        try:
            md_stream = None
            catalog = _get_catalog(pdf)
            if isinstance(catalog, pikepdf.Dictionary):
                md_stream = catalog.get("/Metadata", None)
            if isinstance(md_stream, pikepdf.Stream):
                report["xmp"] = _parse_xmp(md_stream.read_bytes())
            else:
                # best-effort fallback via open_metadata when available
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
