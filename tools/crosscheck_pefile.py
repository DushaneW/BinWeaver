"""Differential test: compares binweaver-cli JSON output with pefile.

    pip install pefile
    python tools/crosscheck_pefile.py <binweaver-cli> <file-or-dir>... [--limit N] [--verbose]

For every PE file both tools can parse, the script compares sections, imports
(regular and delay-load), exports (ordinal, name, RVA, forwarder), imphash,
Rich header entries, resource leaves (RVA, size), VS_FIXEDFILEINFO versions,
and load-config fields (security cookie, CFG function count). It prints one
line per mismatch and a summary; exit status 1 when any mismatch was found.

Known pefile limitations, counted as "skipped" rather than reported:
  * exports when pefile stops at 8192 ordinal entries ("Assuming corrupt");
    export names are compared after truncating to pefile's 512-byte limit.
  * Rich headers that pefile decodes from a fixed 0x80 start without a "DanS"
    marker (it warns "not in Microsoft format"); BinWeaver locates "DanS".
"""
import json
import os
import subprocess
import sys
import time

import pefile

ORDINAL_NAMED_DLLS = {"ws2_32.dll", "wsock32.dll", "oleaut32.dll"}


def s(b):
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else (b or "")


def collect(paths, limit):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.lower().endswith((".dll", ".exe", ".sys", ".mui")):
                    f = os.path.join(p, name)
                    if os.path.isfile(f) and os.path.getsize(f) < 64 << 20:
                        out.append(f)
        else:
            out.append(p)
    return out[:limit] if limit else out


SKIPS = {}


def skip(reason):
    SKIPS[reason] = SKIPS.get(reason, 0) + 1


def compare(cli, path, verbose):
    issues = []
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:  # pefile rejects it: nothing to compare
        return None, ["pefile-error: %s" % e]
    # Antivirus software can briefly deny starting a freshly built executable.
    for attempt in range(5):
        try:
            proc = subprocess.run([cli, "inspect", path, "--json"], capture_output=True)
            break
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.5 * (attempt + 1))
    try:
        bw = json.loads(proc.stdout.decode("utf-8", "replace"))
    except json.JSONDecodeError as e:
        return pe, ["binweaver produced invalid JSON: %s" % e]

    def check(category, ours, theirs):
        if ours != theirs:
            detail = ""
            if verbose:
                detail = "\n      ours:   %r\n      pefile: %r" % (ours, theirs)
            issues.append("%s differs%s" % (category, detail))

    check("sections", [(x["name"], x["address"], x["virtual_size"], x["size"]) for x in bw["sections"]],
          [(s(x.Name).rstrip("\0"), x.VirtualAddress, x.Misc_VirtualSize, x.SizeOfRawData) for x in pe.sections])

    theirs_imports = []
    for attr, delayed in (("DIRECTORY_ENTRY_IMPORT", False), ("DIRECTORY_ENTRY_DELAY_IMPORT", True)):
        for entry in getattr(pe, attr, []):
            for imp in entry.imports:
                # pefile invents names for some ordinal imports (ordlookup);
                # compare what the file actually contains.
                by_ordinal = getattr(imp, "import_by_ordinal", False) or not imp.name
                theirs_imports.append((s(entry.dll), None if by_ordinal else s(imp.name),
                                       imp.ordinal if by_ordinal else None, delayed))
    ours_imports = [(x["library"], x["name"] or None, x["ordinal"], x["delayed"]) for x in bw["imports"]]
    check("imports", sorted(ours_imports, key=repr), sorted(theirs_imports, key=repr))

    theirs_exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.address == 0:
                continue
            theirs_exports.append((e.ordinal, s(e.name), e.address, s(e.forwarder)))
    # BinWeaver joins aliases sharing one address slot into "a, b"; expand them.
    ours_exports = []
    for x in bw["exports"]:
        for name in (x["name"].split(", ") if x["name"] else [""]):
            ours_exports.append((x["ordinal"], name[:pefile.MAX_SYMBOL_NAME_LENGTH], x["rva"], x["forwarder"]))
    theirs_exports = [(o, n[:pefile.MAX_SYMBOL_NAME_LENGTH], a, f) for o, n, a, f in theirs_exports]
    if any("more than 8192 ordinal entries" in w for w in pe.get_warnings()):
        skip("exports: pefile 8192-ordinal limit")
    else:
        check("exports", sorted(ours_exports), sorted(theirs_exports))

    ordinal_special = any(s(e.dll).lower() in ORDINAL_NAMED_DLLS and
                          any(getattr(i, "import_by_ordinal", False) or not i.name for i in e.imports)
                          for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    check("imphash", bw.get("imphash", ""), pe.get_imphash())

    if pe.RICH_HEADER is not None and not pe.RICH_HEADER.clear_data.startswith(b"DanS"):
        skip("rich: pefile decoded without DanS")
    elif pe.RICH_HEADER is not None:
        vals = pe.RICH_HEADER.values
        theirs_rich = [(vals[i] >> 16, vals[i] & 0xffff, vals[i + 1]) for i in range(0, len(vals) - 1, 2)]
        check("rich", [(x["product_id"], x["build"], x["count"]) for x in bw["rich"]], theirs_rich)
    else:
        check("rich", bw["rich"], [])

    theirs_res = []

    def walk(d, depth):
        for e in d.entries:
            if hasattr(e, "directory"):
                if depth < 8:
                    walk(e.directory, depth + 1)
            elif hasattr(e, "data"):
                theirs_res.append((e.data.struct.OffsetToData, e.data.struct.Size))
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        walk(pe.DIRECTORY_ENTRY_RESOURCE, 0)
    check("resources", sorted((x["rva"], x["size"]) for x in bw["resources"]), sorted(theirs_res))

    exc = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", None)
    if exc is not None or bw.get("functions"):
        theirs_fn = sorted({(e.struct.BeginAddress, e.struct.EndAddress, e.struct.UnwindData) for e in (exc or [])
                            if (e.struct.BeginAddress, e.struct.EndAddress, e.struct.UnwindData) != (0, 0, 0)})
        check("functions", sorted({(f["begin"], f["end"], f["unwind"]) for f in bw.get("functions", [])}), theirs_fn)
        # UNWIND_INFO fields (pefile decodes them per entry).
        theirs_uw = sorted({(e.struct.BeginAddress, u.Version, u.Flags, u.SizeOfProlog, u.CountOfCodes, u.FrameRegister,
                             u.FrameOffset, getattr(u, "ExceptionHandler", 0) if u.Flags & 3 and not u.Flags & 4 else 0)
                            for e in (exc or []) for u in [e.unwindinfo] if u is not None})
        ours_uw = sorted({(f["begin"], f["unwind_version"], f["unwind_flags"], f["prolog_size"], f["code_count"],
                           f["frame_register"], f["frame_offset"], f["handler"]) for f in bw.get("functions", [])
                          if f["begin"] in {t[0] for t in theirs_uw}})
        check("unwind info", ours_uw, theirs_uw)

    # RT_STRING: pefile merges all languages of a block into one dict (last wins).
    def escape(t):
        return "".join("\\x%02x" % ord(c) if ord(c) < 0x20 or ord(c) == 0x7f else c for c in t)
    theirs_str = {}
    for t in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
        if t.id == 6:
            for n in t.directory.entries:
                for k, v in getattr(n.directory, "strings", {}).items():
                    theirs_str[k] = escape(v)
    # pefile keeps one language per id (last wins); BinWeaver keeps all. Every
    # pefile string must be among BinWeaver's strings for the same id.
    ours_str = {}
    for r in bw.get("resource_strings", []):
        ours_str.setdefault(r["id"], set()).add(r["text"])
    check("resource strings", sorted(ours_str), sorted(theirs_str))
    missing = [k for k, v in theirs_str.items() if v not in ours_str.get(k, set())]
    check("resource string text", missing, [])

    check("debug entries", [(e["type"], e["size"], e["rva"], e["pointer"]) for e in bw.get("debug_entries", [])],
          [(e.struct.Type, e.struct.SizeOfData, e.struct.AddressOfRawData, e.struct.PointerToRawData)
           for e in getattr(pe, "DIRECTORY_ENTRY_DEBUG", [])])

    props = bw.get("properties", {})
    if getattr(pe, "VS_FIXEDFILEINFO", None):
        f = pe.VS_FIXEDFILEINFO[0]
        ver = "%d.%d.%d.%d" % (f.FileVersionMS >> 16, f.FileVersionMS & 0xffff, f.FileVersionLS >> 16, f.FileVersionLS & 0xffff)
        check("file version", props.get("File version"), ver)

    if hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        cookie = getattr(lc, "SecurityCookie", None)
        if cookie is not None and "Security cookie (/GS)" in props:
            check("security cookie", props["Security cookie (/GS)"], hex(cookie) if cookie else "none")
        table = getattr(lc, "GuardCFFunctionTable", 0)
        count = getattr(lc, "GuardCFFunctionCount", None)
        if table and count is not None:
            check("cfg count", props.get("CFG function table"), "%d entries" % count)

    if not bw.get("structurally_valid", True):
        issues.append("binweaver reports structural errors: %s" %
                      [d["code"] for d in bw["diagnostics"] if d["severity"] == "error"][:5])
    return pe, issues


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    limit = 0
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
        args.remove(str(limit))
    verbose = "--verbose" in sys.argv
    cli, inputs = args[0], args[1:]
    files = collect(inputs, limit)
    compared = mismatched = skipped = 0
    by_category = {}
    for f in files:
        pe, issues = compare(cli, f, verbose)
        if pe is None:
            skipped += 1
            continue
        compared += 1
        if issues:
            mismatched += 1
            for i in issues:
                key = i.split(" ")[0]
                by_category[key] = by_category.get(key, 0) + 1
                print("%s: %s" % (f, i))
    print("\ncompared %d files (%d skipped: pefile could not parse), %d with differences" % (compared, skipped, mismatched))
    for k, v in sorted(by_category.items()):
        print("  %-20s %d" % (k, v))
    if SKIPS:
        print("known pefile limitations (comparison skipped):")
        for k, v in sorted(SKIPS.items()):
            print("  %-45s %d" % (k, v))
    return 1 if mismatched else 0


if __name__ == "__main__":
    sys.exit(main())
